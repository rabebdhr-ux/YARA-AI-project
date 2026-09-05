/**
 * YARA AI Platform — File Analysis
 * Upload, validation, and progress UI (frontend only)
 */

(function () {
  'use strict';

  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const selectFileBtn = document.getElementById('selectFileBtn');
  const filePreview = document.getElementById('filePreview');
  const previewName = document.getElementById('previewName');
  const previewSize = document.getElementById('previewSize');
  const previewType = document.getElementById('previewType');
  const removeFileBtn = document.getElementById('removeFileBtn');
  const uploadActions = document.getElementById('uploadActions');
  const uploadError = document.getElementById('uploadError');
  const analysisForm = document.getElementById('analysisForm');
  const analysisProgress = document.getElementById('analysisProgress');
  const progressSteps = document.getElementById('progressSteps');
  const progressStatus = document.getElementById('progressStatus');

  if (!dropZone) return;

  let selectedFile = null;

  function showError(message) {
    uploadError.textContent = message;
    uploadError.hidden = false;
  }

  function hideError() {
    uploadError.hidden = true;
    uploadError.textContent = '';
  }

  function handleFile(file) {
    hideError();
    const validation = window.validateFile(file);
    if (!validation.valid) {
      showError(validation.error);
      clearFile();
      return;
    }

    selectedFile = file;
    previewName.textContent = file.name;
    previewSize.textContent = window.formatFileSize(file.size);
    previewType.textContent = window.getFileExtension(file.name);
    filePreview.hidden = false;
    uploadActions.hidden = false;
    dropZone.style.display = 'none';
  }

  function clearFile() {
    selectedFile = null;
    fileInput.value = '';
    filePreview.hidden = true;
    uploadActions.hidden = true;
    dropZone.style.display = '';
  }

  selectFileBtn?.addEventListener('click', function (e) {
    e.stopPropagation();
    fileInput.click();
  });

  dropZone.addEventListener('click', function () {
    fileInput.click();
  });

  fileInput.addEventListener('change', function () {
    if (fileInput.files.length) handleFile(fileInput.files[0]);
  });

  removeFileBtn?.addEventListener('click', clearFile);

  /* Drag and Drop */
  ['dragenter', 'dragover'].forEach(function (event) {
    dropZone.addEventListener(event, function (e) {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(function (event) {
    dropZone.addEventListener(event, function (e) {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('dragover');
    });
  });

  dropZone.addEventListener('drop', function (e) {
    const files = e.dataTransfer.files;
    if (files.length) handleFile(files[0]);
  });

  /* Analysis Progress (demo simulation — replace with backend polling) */
  const STEPS = [
    'Uploading file',
    'Extracting features',
    'Scanning with YARA',
    'Running AI analysis',
    'Generating report'
  ];

  function setStepStatus(index, status) {
    const steps = progressSteps?.querySelectorAll('.progress-step');
    if (!steps || !steps[index]) return;
    const step = steps[index];
    step.className = 'progress-step progress-step--' + status;
  }

  function simulateProgress(callback) {
    analysisProgress.hidden = false;
    uploadActions.hidden = true;
    progressStatus.textContent = 'In progress…';

    let current = 0;

    function runStep() {
      if (current > 0) setStepStatus(current - 1, 'completed');
      if (current >= STEPS.length) {
        progressStatus.textContent = 'Complete';
        if (callback) callback();
        return;
      }
      setStepStatus(current, 'running');
      current++;
      setTimeout(runStep, 1200);
    }

    runStep();
  }

    analysisForm?.addEventListener('submit', function (e) {
    if (!selectedFile) {
      e.preventDefault();
      showError('Please select a file before starting analysis.');
      return;
    }

    /* Submit the form via fetch */
    e.preventDefault();
    simulateProgress(function () {
      /* Submit the form via fetch */
      const formData = new FormData(analysisForm);
      const action = analysisForm.getAttribute('action') || '/scan';
      
      fetch(action, {
        method: 'POST',
        body: formData
      })
      .then(response => {
        if (response.redirected) {
          /* Flask redirected us to the result page */
          window.location.href = response.url;
        } else if (response.ok) {
          return response.json();
        } else {
          throw new Error('Upload failed: ' + response.statusText);
        }
      })
      .catch(error => {
        showError('Error: ' + error.message);
        console.error('Upload error:', error);
      });
    });
  });
})();
