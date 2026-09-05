"""
YARA Scanner Module
Handles loading, compiling, and running YARA rules against files
"""

import yara
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class YARAScanner:
    """
    YARA Scanner for malware detection
    Loads and compiles YARA rules, scans files
    """
    
    def __init__(self, rules_dir='yara_rules'):
        """
        Initialize YARA scanner with rules from specified directory
        
        Args:
            rules_dir: Directory containing .yar/.yara rule files
        """
        self.rules_dir = rules_dir
        self.rules = None
        self.errors = []
        self._load_rules()
    
    def _load_rules(self):
        """Load and compile all YARA rules from the rules directory"""
        self.errors = []
        
        # Create rules directory if it doesn't exist
        os.makedirs(self.rules_dir, exist_ok=True)
        
        # Find all .yar and .yara files
        rule_files = {}
        rules_path = Path(self.rules_dir)
        
        for pattern in ['*.yar', '*.yara']:
            for rule_file in rules_path.glob(pattern):
                namespace = rule_file.stem
                rule_files[namespace] = str(rule_file)
        
        if not rule_files:
            logger.warning(f"No YARA rules found in {self.rules_dir}")
            self.rules = None
            return
        
        try:
            # Compile rules with namespaces
            self.rules = yara.compile(filepaths=rule_files)
            logger.info(f"Loaded {len(rule_files)} YARA rule files")
        except yara.Error as e:
            logger.error(f"Error compiling YARA rules: {str(e)}")
            self.errors.append(f"YARA compilation error: {str(e)}")
            self.rules = None
    
    def scan_file(self, file_path):
        """
        Scan a file with YARA rules
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            dict with scan results
        """
        result = {
            'matches': [],
            'total_matches': 0,
            'errors': []
        }
        
        # Check if file exists
        if not os.path.exists(file_path):
            result['errors'].append(f"File not found: {file_path}")
            return result
        
        # Check if rules are loaded
        if not self.rules:
            result['errors'].append("No YARA rules available for scanning")
            return result
        
        try:
            # Scan file
            matches = self.rules.match(file_path)
            
            # Process matches
            for match in matches:
                rule_data = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags if hasattr(match, 'tags') else [],
                    'strings': []
                }
                
                # Extract matched strings (safely)
                #
                # yara-python >= 4.3 exposes match.strings as a list of
                # StringMatch objects (identifier + instances), not the
                # legacy (offset, identifier, data) tuples. Support both
                # so this keeps working across yara-python versions.
                if hasattr(match, 'strings'):
                    for string_match in match.strings:
                        try:
                            if isinstance(string_match, tuple) and len(string_match) >= 3:
                                # Legacy yara-python (< 4.3)
                                candidates = [(
                                    string_match[0],
                                    string_match[1],
                                    string_match[2]
                                )]
                            else:
                                # Modern yara-python StringMatch object
                                identifier = getattr(string_match, 'identifier', '')
                                instances = getattr(string_match, 'instances', [])
                                candidates = [
                                    (
                                        getattr(instance, 'offset', None),
                                        identifier,
                                        getattr(instance, 'matched_data', b'')
                                    )
                                    for instance in instances
                                ]

                            for offset, identifier, data in candidates:
                                # Only include if we can safely represent it
                                try:
                                    if isinstance(data, bytes):
                                        data_str = data.decode('utf-8', errors='ignore')
                                    else:
                                        data_str = str(data)

                                    if len(data_str) < 200:  # Only strings under 200 chars
                                        rule_data['strings'].append({
                                            'identifier': identifier,
                                            'data': data_str,
                                            'offset': offset
                                        })
                                except:
                                    pass

                                # Cap evidence size per rule to keep results
                                # (and the AI prompt payload) reasonably sized
                                if len(rule_data['strings']) >= 20:
                                    break
                        except:
                            pass
                
                result['matches'].append(rule_data)
            
            result['total_matches'] = len(result['matches'])
            logger.info(f"Scan complete: {file_path} - {len(matches)} matches")
            
        except yara.Error as e:
            logger.error(f"YARA scan error: {str(e)}")
            result['errors'].append(f"YARA scan error: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during scanning: {str(e)}")
            result['errors'].append(f"Scanning error: {str(e)}")
        
        return result
    
    def get_rule_info(self, rule_name):
        """
        Get information about a specific rule
        
        Args:
            rule_name: Name of the rule
            
        Returns:
            dict with rule metadata or None
        """
        if not self.rules:
            return None
        
        try:
            for match in self.rules.match(''):
                if match.rule == rule_name:
                    return {
                        'name': match.rule,
                        'namespace': match.namespace,
                        'tags': match.tags if hasattr(match, 'tags') else []
                    }
        except:
            pass
        
        return None