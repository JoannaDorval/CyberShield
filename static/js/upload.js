// Upload functionality for TARA application

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('uploadForm');
    const submitBtn = document.getElementById('submitBtn');
    const progressDiv = document.querySelector('.upload-progress');
    const progressBar = progressDiv.querySelector('.progress-bar');
    
    const uploadZones = {
        threatModel: document.getElementById('threatModelZone'),
        blockDiagram: document.getElementById('blockDiagramZone'),
        crossmap: document.getElementById('crossmapZone')
    };
    
    const fileInputs = {
        threatModel: document.getElementById('threatModel'),
        blockDiagram: document.getElementById('blockDiagram'),
        crossmap: document.getElementById('crossmap')
    };
    
    // Initialize upload zones
    Object.keys(uploadZones).forEach(key => {
        const zone = uploadZones[key];
        const input = fileInputs[key];
        
        // Drag and drop handlers
        zone.addEventListener('dragover', handleDragOver);
        zone.addEventListener('dragenter', handleDragEnter);
        zone.addEventListener('dragleave', handleDragLeave);
        zone.addEventListener('drop', (e) => handleDrop(e, input));
        
        // File input change handler
        input.addEventListener('change', (e) => handleFileSelect(e, zone));
        
        // Click handler for zone
        zone.addEventListener('click', () => input.click());
    });
    
    // Form submission handler
    form.addEventListener('submit', handleFormSubmit);
    
    function handleDragOver(e) {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'copy';
    }
    
    function handleDragEnter(e) {
        e.preventDefault();
        e.currentTarget.classList.add('dragover');
    }
    
    function handleDragLeave(e) {
        e.preventDefault();
        if (!e.currentTarget.contains(e.relatedTarget)) {
            e.currentTarget.classList.remove('dragover');
        }
    }
    
    function handleDrop(e, input) {
        e.preventDefault();
        const zone = e.currentTarget;
        zone.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            input.files = files;
            handleFileSelect({ target: input }, zone);
        }
    }
    
    function handleFileSelect(e, zone) {
        const file = e.target.files[0];
        const fileInfo = zone.querySelector('.file-info');
        const filename = fileInfo.querySelector('.filename');
        const uploadContent = zone.querySelector('.upload-content');
        
        if (file) {
            // Validate file size (50MB limit)
            if (file.size > 50 * 1024 * 1024) {
                alert('File size exceeds 50MB limit. Please choose a smaller file.');
                e.target.value = '';
                return;
            }
            
            // Show file info
            filename.textContent = file.name;
            fileInfo.style.display = 'block';
            uploadContent.style.display = 'none';
            zone.classList.add('file-selected');
            
            // Update icon in file info based on file type
            const icon = fileInfo.querySelector('i');
            if (file.type.startsWith('image/')) {
                icon.setAttribute('data-feather', 'image');
            } else {
                icon.setAttribute('data-feather', 'file');
            }
            feather.replace();
        } else {
            // Reset zone
            fileInfo.style.display = 'none';
            uploadContent.style.display = 'block';
            zone.classList.remove('file-selected');
        }
        
        updateSubmitButton();
    }
    
    function updateSubmitButton() {
        const allFiles = Object.values(fileInputs).every(input => input.files.length > 0);
        submitBtn.disabled = !allFiles;
        
        if (allFiles) {
            submitBtn.classList.remove('btn-outline-primary');
            submitBtn.classList.add('btn-primary');
        } else {
            submitBtn.classList.remove('btn-primary');
            submitBtn.classList.add('btn-outline-primary');
        }
    }
    
    function handleFormSubmit(e) {
        e.preventDefault();
        
        // Validate all files are selected
        const missingFiles = Object.keys(fileInputs).filter(key => fileInputs[key].files.length === 0);
        if (missingFiles.length > 0) {
            alert('Please select all required files before submitting.');
            return;
        }
        
        // Show progress
        showProgress();
        
        // Create FormData and submit
        const formData = new FormData(form);
        
        fetch(form.action, {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                return response.text().then(text => {
                    throw new Error('Upload failed');
                });
            }
        })
        .catch(error => {
            console.error('Upload error:', error);
            hideProgress();
            alert('Upload failed. Please try again.');
        });
    }
    
    function showProgress() {
        // Hide form and show progress
        form.style.display = 'none';
        progressDiv.style.display = 'block';
        
        // Animate progress bar
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.random() * 15;
            if (progress > 90) {
                progress = 90;
                clearInterval(interval);
            }
            progressBar.style.width = progress + '%';
        }, 500);
    }
    
    function hideProgress() {
        progressDiv.style.display = 'none';
        form.style.display = 'block';
        progressBar.style.width = '0%';
    }
    
    // File type validation
    function validateFileType(file, allowedTypes) {
        const extension = file.name.split('.').pop().toLowerCase();
        return allowedTypes.includes(extension);
    }
    
    // Additional file input validation
    fileInputs.threatModel.addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file && !validateFileType(file, ['json', 'yaml', 'yml'])) {
            alert('Threat model must be a JSON or YAML file.');
            e.target.value = '';
            handleFileSelect(e, uploadZones.threatModel);
        }
    });
    
    fileInputs.blockDiagram.addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file && !validateFileType(file, ['svg', 'png', 'jpg', 'jpeg'])) {
            alert('Block diagram must be an SVG, PNG, or JPEG file.');
            e.target.value = '';
            handleFileSelect(e, uploadZones.blockDiagram);
        }
    });
    
    fileInputs.crossmap.addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file && !validateFileType(file, ['json'])) {
            alert('Cross-mapping data must be a JSON file.');
            e.target.value = '';
            handleFileSelect(e, uploadZones.crossmap);
        }
    });
    
    // Initialize submit button state
    updateSubmitButton();
});

// Prevent default drag behaviors on document
document.addEventListener('dragover', function(e) {
    e.preventDefault();
});

document.addEventListener('drop', function(e) {
    e.preventDefault();
});
