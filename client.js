// API helper function with enhanced error handling and timeout
async function api(action, data = null) {
    const url = `/api/${action}`;
    const options = {
        method: data ? 'POST' : 'GET',
        headers: {'Content-Type': 'application/json'},
        ...(data && { body: JSON.stringify(data) })
    };
   
    try {
        const response = await fetch(url, options);
        const contentType = response.headers.get('content-type');
       
        if (!contentType || !contentType.includes('application/json')) {
            const textResponse = await response.text();
            return {
                success: false,
                message: `Server returned non-JSON response: ${response.status} ${response.statusText}`
            };
        }
       
        return await response.json();
       
    } catch (error) {
        const errorMessages = {
            'TypeError': 'Network error: Unable to connect to server. Check if Flask app is running.',
            'SyntaxError': 'Server returned invalid JSON response. Check Flask console for errors.'
        };
       
        return {
            success: false,
            message: errorMessages[error.name] || error.message || 'Unknown network error occurred'
        };
    }
}

// UTILITIES

let copyTexts = {};
let iocFiles = {};

// Duplicate tracking
let fileSignatureTracker = {}; // Track file signatures per IOC index

// Generate unique file signature for duplicate detection
function generateFileSignature(file) {
    return `${file.name}_${file.size}_${file.lastModified || Date.now()}_${file.type}`;
}

// Check if file is duplicate within specific IOC
function isFileAlreadyAdded(file, iocIndex) {
    if (!fileSignatureTracker[iocIndex]) {
        fileSignatureTracker[iocIndex] = new Set();
    }
   
    const signature = generateFileSignature(file);
    return fileSignatureTracker[iocIndex].has(signature);
}

// Track file as added
function trackFileAsAdded(file, iocIndex) {
    if (!fileSignatureTracker[iocIndex]) {
        fileSignatureTracker[iocIndex] = new Set();
    }
   
    const signature = generateFileSignature(file);
    fileSignatureTracker[iocIndex].add(signature);
}

// Remove file from tracking
function untrackFile(file, iocIndex) {
    if (fileSignatureTracker[iocIndex]) {
        const signature = generateFileSignature(file);
        fileSignatureTracker[iocIndex].delete(signature);
    }
}

// Clear all tracking for IOC
function clearFileTracking(iocIndex) {
    if (fileSignatureTracker[iocIndex]) {
        fileSignatureTracker[iocIndex].clear();
    }
}

// clipboard copy
async function copyToClipboard(text, buttonElement) {
    if (typeof text === 'number' || (typeof text === 'string' && copyTexts[text])) {
        text = copyTexts[text] || '';
    }
   
    if (buttonElement.classList.contains('copying')) return;
    buttonElement.classList.add('copying');
   
    let success = false;
   
    // Clipboard API
    if (navigator.clipboard && window.isSecureContext) {
        try {
            await navigator.clipboard.writeText(text);
            success = true;
        } catch (e) {
            console.warn('Clipboard API failed:', e);
        }
    }

    // Fallback to execCommand
    if (!success) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.cssText = 'position:fixed;left:-9999px;opacity:0';
        document.body.appendChild(textArea);
        textArea.select();
       
        try {
            success = document.execCommand('copy');
        } catch (e) {
            console.error('execCommand failed:', e);
        }
       
        document.body.removeChild(textArea);
    }
   
    // Update button UI
    if (success) {
        const original = buttonElement.innerHTML;
        buttonElement.innerHTML = '<i class="fas fa-check"></i> Copied!';
        buttonElement.classList.add('copied');
        setTimeout(() => {
            buttonElement.innerHTML = original;
            buttonElement.classList.remove('copied', 'copying');
        }, 2000);
    } else {
        buttonElement.classList.remove('copying');
        prompt('Auto-copy failed. Please copy manually:', text);
    }
   
    return success;
}

// MODE SWITCHING

// Mode configuration
const MODE_CONFIG = {
    monitor: {
        hide: ['case_type_group', 'malware_type_group'],
        show: ['threat_cat_group'],
        required: ['threat_category'],
        optional: []
    },
    threat: {
        hide: ['threat_cat_group', 'malware_type_group'],
        show: ['case_type_group'],
        required: ['case_type'],
        optional: []
    }
};

function setMode(mode, buttonElement) {
    // Update UI
    document.querySelectorAll('.mode-option').forEach(btn => btn.classList.remove('active'));
    buttonElement.classList.add('active');
    document.getElementById('case_mode_val').value = mode;

    const config = MODE_CONFIG[mode] || MODE_CONFIG.threat;
   
    // Apply configuration
    config.hide.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.style.display = 'none';
            const select = element.querySelector('select');
            if (select) {
                select.removeAttribute('required');
                select.value = '';
                select.disabled = true;
            }
        }
    });
   
    config.show.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.style.display = 'block';
            const select = element.querySelector('select');
            if (select) {
                select.setAttribute('required', 'required');
                select.disabled = false;
            }
        }
    });

    // Clear dynamic fields and results
    const dynamicFields = document.getElementById('dynamicFields');
    if (dynamicFields) dynamicFields.innerHTML = '';
   
    const processingResult = document.getElementById('processingResult');
    if (processingResult) processingResult.innerHTML = '';

    // Update IOC label if function exists
    if (typeof updateIOCLabel === "function") {
        updateIOCLabel();
    }
}

// IOC LABEL UPDATES

const IOC_LABELS = {
    monitor: {
        label: 'Domain Names <span class="required-mark">*</span>',
        placeholder: 'Enter domains (one per line or comma-separated):\nexample.com\nsuspicious-site.net\nOR\nexample.com, suspicious-site.net',
        required: true
    },
    vishing: {
        label: 'Phone Numbers <span class="required-mark">*</span>',
        placeholder: 'Enter phone numbers (one per line or comma-separated):\n+1 (555) 123-4567\n555-987-6543\nOR\n5551234567, 5559876543',
        required: true
    },
    smishing: {
        label: 'Phone Numbers <span class="required-mark">*</span>',
        placeholder: 'Enter phone numbers (one per line or comma-separated):\n+1 (555) 123-4567\n555-987-6543\nOR\n5551234567, 5559876543',
        required: true
    },
    'customer inquiry': {
        label: 'IOCs <span style="color: var(--text-secondary); font-weight: normal;">(Optional)</span>',
        placeholder: 'Optional: Enter URLs, domains, emails, or phone numbers',
        required: false
    },
    other: {
        label: 'IOCs <span class="required-mark">*</span>',
        placeholder: 'Enter any IOCs (URLs, domains, emails, phone numbers):\nhttps://example.com\nuser@example.com\n+1-555-123-4567',
        required: true
    },
    default: {
        label: 'URLs / Domains <span class="required-mark">*</span>',
        placeholder: 'Enter URLs or domains (one per line or comma-separated):\nhttps://suspicious-site.com\nexample.net\nOR\nhttps://site1.com, https://site2.com',
        required: true
    }
};

function updateIOCLabel() {
    const caseType = document.getElementById('case_type').value;
    const mode = document.getElementById('case_mode_val').value;
    const iocGroup = document.getElementById('ioc_group');
    const iocLabel = iocGroup.querySelector('.form-label');
    const iocInput = document.getElementById('ioc_input');
   
    // Handle monitor mode
    if (mode === 'monitor') {
        const config = IOC_LABELS.monitor;
        iocLabel.innerHTML = config.label;
        iocInput.placeholder = config.placeholder;
        iocInput.required = config.required;
        updateDynamicFields('');
        return;
    }
   
    // Handle case type specific labels
    const config = IOC_LABELS[caseType.toLowerCase()] || IOC_LABELS.default;
    iocLabel.innerHTML = config.label;
    iocInput.placeholder = config.placeholder;
    iocInput.required = config.required;
   
    // Show/hide dynamic fields based on case type
    updateDynamicFields(caseType);
}

// DYNAMIC FIELDS

function updateDynamicFields(caseType) {
    const dynamicFields = document.getElementById('dynamicFields');
    dynamicFields.innerHTML = '';
   
    if (caseType.toLowerCase() === 'crimeware') {
        const malwareField = document.createElement('div');
        malwareField.className = 'form-group';
        malwareField.id = 'malware_type_group';
        malwareField.innerHTML = `
            <label class="form-label">
                Malware Type
                <span style="color: var(--text-secondary); font-weight: normal;">(Optional)</span>
            </label>
            <input type="text" name="malware_type" class="form-input" placeholder="e.g., Trojan, Ransomware, Keylogger">
        `;
        dynamicFields.appendChild(malwareField);
    }
}

// SETTINGS MODAL

function openSettings() {
    document.getElementById('settingsModal').style.display = 'block';
    document.body.style.overflow = 'hidden';
   
    api('settings').then(data => {
        // Clear fields
        ['username', 'custid', 'password'].forEach(id => {
            document.getElementById(id).value = '';
        });
       
        // Set masked placeholders
        if (data.username) {
            const masked = maskString(data.username);
            document.getElementById('username').placeholder = masked;
        } else {
            document.getElementById('username').placeholder = 'Enter your username';
        }
       
        if (data.custid) {
            const masked = maskString(data.custid);
            document.getElementById('custid').placeholder = masked;
        } else {
            document.getElementById('custid').placeholder = 'Enter customer ID for domain monitoring features';
        }
       
        document.getElementById('password').placeholder = data.hasPassword ?
            'Password is set (leave blank to keep current)' : 'Enter your password';
    });
}

function closeSettings() {
    document.getElementById('settingsModal').style.display = 'none';
    document.body.style.overflow = '';
}

// Utility function for masking strings
function maskString(str) {
    return str.length > 4
        ? str.substring(0, 2) + '*'.repeat(str.length - 4) + str.substring(str.length - 2)
        : '*'.repeat(str.length);
}

// CONNECTION TESTING

async function testConnection() {
    const button = event.target.closest('button');
    const originalContent = button.innerHTML;
   
    button.disabled = true;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing...';
   
    try {
        const result = await api('test');
        if (result.success) {
            showNotification(`[OK] Connection successful: ${result.message}`, 'success');
        } else {
            showNotification(`[ERROR] Connection failed: ${result.message}`, 'error');
        }
    } catch (error) {
        showNotification(`[ERROR] Connection test error: ${error.message}`, 'error');
    } finally {
        button.disabled = false;
        button.innerHTML = originalContent;
    }
}

// CONFIGURATION REFRESH

async function refreshConfig() {
    const button = event.target.closest('button');
    const originalContent = button.innerHTML;
   
    button.disabled = true;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
   
    try {
        const result = await api('refresh');
        if (result.success) {
            updateDropdowns(result.brands, result.case_types);
            showNotification('[OK] Configuration refreshed successfully', 'success');
        } else {
            showNotification(`[ERROR] Failed to refresh: ${result.message}`, 'error');
        }
    } catch (error) {
        showNotification(`[ERROR] Refresh error: ${error.message}`, 'error');
    } finally {
        button.disabled = false;
        button.innerHTML = originalContent;
    }
}

// NOTIFICATIONS

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
        ${message}
    `;
   
    document.body.appendChild(notification);
    setTimeout(() => notification.classList.add('show'), 10);
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// DROPDOWN UPDATES

function updateDropdowns(brands, types) {
    const selectors = {
        brand: document.querySelectorAll('[name="brand"]'),
        case_type: document.querySelectorAll('[name="case_type"]')
    };
   
    Object.entries(selectors).forEach(([name, elements]) => {
        const options = name === 'brand' ? brands : types;
        const placeholder = name === 'brand' ? 'Select brand...' : 'Select case type...';
       
        elements.forEach(select => {
            const currentValue = select.value;
            select.innerHTML = `<option value="">${placeholder}</option>` +
                options.map(option => `<option value="${option}">${option}</option>`).join('');
            if (options.includes(currentValue)) {
                select.value = currentValue;
            }
        });
    });
}

// IOC PARSING

async function parseAndValidateIOCs() {
    const iocText = document.getElementById('ioc_input').value.trim();
    const caseType = document.getElementById('case_type').value;
    const mode = document.getElementById('case_mode_val').value;
   
    // Validation logic
    if (!iocText && caseType.toLowerCase() === 'customer inquiry') {
        return { success: true, iocs: [''] };
    }
   
    if (!iocText && mode === 'threat' && !caseType) {
        showNotification('Please select a case type first', 'error');
        return { success: false, iocs: [] };
    }
   
    if (!iocText) {
        showNotification('Please enter at least one IOC', 'error');
        return { success: false, iocs: [] };
    }
   
    // Parse IOCs using backend
    const result = await api('parse', { urls: iocText });
   
    if (result.success && result.urls.length > 0) {
        return { success: true, iocs: result.urls };
    } else {
        showNotification('No valid IOCs found. Please check your input.', 'error');
        return { success: false, iocs: [] };
    }
}

// FILE HANDLING SYSTEM

// FILE HANDLING GLOBALS
let processingFiles = new Set();

// FILE TYPE DETECTION UTILITIES

// Detect image type from file headers
function detectImageTypeFromHeader(arrayBuffer) {
    const arr = new Uint8Array(arrayBuffer).subarray(0, 8);
    let header = '';
    for (let i = 0; i < arr.length; i++) {
        header += arr[i].toString(16).padStart(2, '0');
    }
   
    const signatures = {
        '89504e47': { type: 'image/png', extension: 'png' },
        '47494638': { type: 'image/gif', extension: 'gif' },
        'ffd8ffe0': { type: 'image/jpeg', extension: 'jpg' },
        'ffd8ffe1': { type: 'image/jpeg', extension: 'jpg' },
        'ffd8ffe2': { type: 'image/jpeg', extension: 'jpg' },
        '52494646': { type: 'image/webp', extension: 'webp' },
        '49492a00': { type: 'image/tiff', extension: 'tiff' },
        '4d4d002a': { type: 'image/tiff', extension: 'tiff' },
        '424d': { type: 'image/bmp', extension: 'bmp' }
    };
   
    for (const [sig, info] of Object.entries(signatures)) {
        if (header.startsWith(sig)) return info;
    }
    return null;
}

// Process email image files
function processEmailImage(file, index) {
    const reader = new FileReader();
    reader.onload = function(e) {
        const imageInfo = detectImageTypeFromHeader(e.target.result);
       
        if (imageInfo) {
            const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
            const fileName = `email-image-${timestamp}.${imageInfo.extension}`;
           
            const correctedFile = new File([file], fileName, {
                type: imageInfo.type,
                lastModified: Date.now()
            });
           
            addFilesToIOC(index, [correctedFile]);
            showPasteNotification(`Email image detected and converted to ${imageInfo.extension.toUpperCase()}`, 'success');
        } else {
            addFilesToIOC(index, [file]);
        }
    };
    reader.readAsArrayBuffer(file);
}

// Process data URL images (screenshots)
function processDataURLImage(url, index) {
    fetch(url)
        .then(res => res.blob())
        .then(blob => {
            const file = new File([blob], generateFilename({type: blob.type}), {
                type: blob.type || 'image/png',
                lastModified: Date.now()
            });
            addFilesToIOC(index, [file]);
            showPasteNotification('Image pasted successfully', 'success');
        })
        .catch(() => {
            showPasteNotification('Failed to process pasted image', 'error');
        });
}

// File utilities
const FILE_ICONS = {
    'pdf': 'fas fa-file-pdf text-red-500',
    'doc': 'fas fa-file-word text-blue-500',
    'docx': 'fas fa-file-word text-blue-500',
    'xls': 'fas fa-file-excel text-green-500',
    'xlsx': 'fas fa-file-excel text-green-500',
    'png': 'fas fa-file-image text-purple-500',
    'jpg': 'fas fa-file-image text-purple-500',
    'jpeg': 'fas fa-file-image text-purple-500',
    'gif': 'fas fa-file-image text-purple-500',
    'txt': 'fas fa-file-alt text-gray-500',
    'eml': 'fas fa-envelope text-orange-500',
    'msg': 'fas fa-envelope text-orange-500',
    'zip': 'fas fa-file-archive text-yellow-500',
    'rar': 'fas fa-file-archive text-yellow-500',
    '7z': 'fas fa-file-archive text-yellow-500'
};

function getFileIcon(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    return FILE_ICONS[ext] || 'fas fa-file text-gray-400';
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function generateFilename(file, contentType = null) {
    const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
   
    if (file.name && file.name !== 'blob' && !file.name.startsWith('image')) {
        return file.name;
    }
   
    const type = contentType || file.type;
   
    if (type.startsWith('image/')) {
        const ext = type.split('/')[1] || 'png';
        return `screenshot-${timestamp}.${ext}`;
    }
   
    if (type === 'text/plain') {
        return `pasted-text-${timestamp}.txt`;
    }
   
    if (type === 'text/html') {
        return `pasted-content-${timestamp}.html`;
    }
   
    return `pasted-file-${timestamp}.txt`;
}

// Create a properly named file with unique timestamp
function createUniqueFile(file) {
    const properName = generateFilename(file);
    if (properName !== file.name) {
        return new File([file], properName, {
            type: file.type,
            lastModified: Date.now()
        });
    } else {
        return new File([file], file.name, {
            type: file.type,
            lastModified: Date.now()
        });
    }
}

// addFilesToIOC with duplicate prevention
function addFilesToIOC(index, files) {
	if (!iocFiles[index]) {
        iocFiles[index] = [];
    }
   
    // SURGICAL FIX: Create unique processing key to prevent rapid-fire duplicates
    const fileNames = Array.from(files).map(f => f.name).sort().join('|');
    const processingKey = `${index}-${Date.now()}-${fileNames}`;
   
    if (processingFiles.has(processingKey)) {
        console.log('Files already being processed, skipping duplicate');
        return;
    }
   
    processingFiles.add(processingKey);
   
    try {
        const newFiles = [];
        const skippedFiles = [];
       
        Array.from(files).forEach(file => {
            const uniqueFile = createUniqueFile(file);
           
            // Check for duplicates using content-based detection
            if (isFileAlreadyAdded(uniqueFile, index)) {
                console.log('Skipping duplicate file:', uniqueFile.name);
                skippedFiles.push(uniqueFile.name);
                return;
            }
           
            // Add file and track it
            iocFiles[index].push(uniqueFile);
            trackFileAsAdded(uniqueFile, index);
            newFiles.push(uniqueFile);
        });
       
        // Update UI only if we added new files
        if (newFiles.length > 0) {
            updateFileDisplay(index);
            updateHiddenInputs(index);
        }
       
        // Show notification about results
        if (newFiles.length > 0 && skippedFiles.length > 0) {
            showPasteNotification(`Added ${newFiles.length} file(s), skipped ${skippedFiles.length} duplicate(s)`, 'success');
        } else if (newFiles.length > 0) {
            showPasteNotification(`Added ${newFiles.length} file(s) successfully`, 'success');
        } else if (skippedFiles.length > 0) {
            showPasteNotification(`All ${skippedFiles.length} file(s) were duplicates - skipped`, 'info');
        }
       
        // console.log('New files added:', newFiles.length);
        // console.log('Duplicates skipped:', skippedFiles.length);
       
    } finally {
        // Clean up processing key after a delay
        setTimeout(() => {
            processingFiles.delete(processingKey);
        }, 500);
    }
}

// Add this function to clean up ALL paste listeners
function cleanupAllPasteListeners() {
    // Remove global paste listener
    document.removeEventListener('paste', globalPasteHandler);
    
    // Remove all zone-specific paste listeners
    document.querySelectorAll('.attachment-zone').forEach(zone => {
        if (zone._pasteHandler) {
            zone.removeEventListener('paste', zone._pasteHandler);
            zone._pasteHandler = null;
        }
        zone.removeEventListener('focus', zoneFocusHandler);
        zone.removeEventListener('blur', zoneBlurHandler);
    });
    
    console.log('Cleaned up all paste listeners');
}

// Clipboard paste handler
function handleClipboardPaste(e, index) {
    e.preventDefault();
   
    const items = Array.from(e.clipboardData.items);
    const files = [];
    let hasProcessedFiles = false; // Track if we've processed any files
   
    // First pass: collect all files
    items.forEach((item, i) => {
        console.log(`Processing item ${i}: kind=${item.kind}, type=${item.type}`);
        if (item.kind === 'file') {
            const file = item.getAsFile();
            if (file) {
				console.log(`Got file from item ${i}:`, file.name, file.type, file.size);
                files.push(file);
                hasProcessedFiles = true;
            }
        }
    });
   
    // If we found files, process them and skip text processing
    if (hasProcessedFiles && files.length > 0) {
        console.log('Processing', files.length, 'files, skipping text processing');
        addFilesToIOC(index, files);
        return;
    }
   
    // Only process text if no files were found
    let textProcessed = false;
    items.forEach(item => {
        if (item.kind === 'string' && item.type === 'text/plain' && !textProcessed) {
            item.getAsString((text) => {
                if (text.trim()) {
                    // console.log('Processing text content as file');
                    const blob = new Blob([text], { type: 'text/plain' });
                    const file = new File([blob], generateFilename({type: 'text/plain'}), {
                        type: 'text/plain',
						lastModified: Date.now()
                    });
                    addFilesToIOC(index, [file]);
                }
            });
            textProcessed = true;
        }
    });
   
    if (!hasProcessedFiles && !textProcessed) {
        console.log('No valid clipboard content found');
    }
}

// DRAG AND DROP HANDLERS

// Drag and drop handler
function handleDrop(e, index) {
    e.preventDefault();
    e.stopPropagation();
   
    const dt = e.dataTransfer;
    const files = [];
    let hasProcessedContent = false;
   
    // ONLY process dt.files - ignore dt.items to prevent duplicates
    if (dt.files && dt.files.length > 0) {
		// console.log('Processing dt.files only:', Array.from(dt.files).map(f => f.name));
        files.push(...Array.from(dt.files));
        hasProcessedContent = true;
    }
   
    // Handle data URLs (screenshots)
    const urlList = dt.getData('text/uri-list');
    if (urlList) {
        const urls = urlList.split('\n').filter(url => url.trim() && url.startsWith('data:'));
        console.log('Processing data URLs:', urls.length);
        urls.forEach(url => {
            processDataURLImage(url, index);
        });
        hasProcessedContent = true;
    }
   
    if (files.length > 0) {
        console.log('Calling addFilesToIOC with files from dt.files only');
        addFilesToIOC(index, files);
    }
   
    if (!hasProcessedContent) {
        console.log('No valid content found in drop operation');
    }
}

// File input handler
function handleFileSelection(input, index) {
	// Create snapshot before clearing
    const fileList = input.files;
   
    // Clear immediately
    input.value = '';
   
    // Process if we had files
    if (fileList && fileList.length > 0) {
        console.log('About to call addFilesToIOC with', fileList.length, 'files');
        addFilesToIOC(index, fileList);
    }
}

// Update file display
function updateFileDisplay(index) {
    const fileList = document.getElementById(`file-list-${index}`);
    const fileItems = document.getElementById(`file-items-${index}`);
    const fileCount = document.getElementById(`file-count-${index}`);
    const dropArea = document.getElementById(`drop-area-${index}`);
   
    if (!iocFiles[index] || iocFiles[index].length === 0) {
        if (fileList) fileList.style.display = 'none';
        if (dropArea) dropArea.style.display = 'flex';
        return;
    }
   
    if (dropArea) dropArea.style.display = 'none';
    if (fileList) fileList.style.display = 'block';
   
    const count = iocFiles[index].length;
    if (fileCount) {
        fileCount.textContent = `${count} file${count !== 1 ? 's' : ''}`;
        fileCount.className = count > 0 ? 'file-count-badge has-files' : 'file-count-badge';
    }
   
    if (fileItems) {
        fileItems.innerHTML = iocFiles[index].map((file, fileIndex) => {
            const size = formatFileSize(file.size);
            const icon = getFileIcon(file.name);
           
            return `
                <div class="file-item">
                    <div class="file-icon">
                        <i class="${icon}"></i>
                    </div>
                    <div class="file-info">
                        <div class="file-name" title="${file.name}">${file.name}</div>
                        <div class="file-size">${size}</div>
                    </div>
                    <button type="button" class="file-remove" onclick="removeFile(${index}, ${fileIndex})" title="Remove file">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;
        }).join('');
    }
   
    // Re-initialize drop zone for add-more area
    setTimeout(() => {
        const addMoreZone = document.getElementById(`add-more-${index}`);
        if (addMoreZone) {
            initializeDropZone(addMoreZone, index);
        }
    }, 100);
}

// Update hidden inputs
function updateHiddenInputs(index) {
    const input = document.getElementById(`file_input_${index}`);
    if (!input) return;
   
    const dt = new DataTransfer();
    if (iocFiles[index]) {
        iocFiles[index].forEach(file => dt.items.add(file));
    }
   
    try {
        input.files = dt.files;
    } catch (e) {
        console.log('Browser does not support direct file assignment');
    }
}

// Modified removeFile with tracking cleanup
function removeFile(iocIndex, fileIndex) {
    if (iocFiles[iocIndex] && iocFiles[iocIndex][fileIndex]) {
        const removedFile = iocFiles[iocIndex][fileIndex];
       
        // Remove from tracking
        untrackFile(removedFile, iocIndex);
       
        // Remove from files array
        iocFiles[iocIndex].splice(fileIndex, 1);
       
        updateFileDisplay(iocIndex);
        updateHiddenInputs(iocIndex);
    }
}

// clearFiles
function clearFiles(index) {
    // Clear tracking for this IOC
    clearFileTracking(index);
   
    iocFiles[index] = [];
    const input = document.getElementById(`file_input_${index}`);
    if (input) input.value = '';
    updateFileDisplay(index);
}

// Initialize drop zone
function initializeDropZone(element, index) {
    // Remove any existing listeners to prevent stacking
    const existingHandler = element._dropHandler;
    if (existingHandler) {
        ['dragenter', 'dragover', 'dragleave', 'drop', 'click'].forEach(eventName => {
            element.removeEventListener(eventName, existingHandler[eventName]);
        });
    }
   
    // Create new handler object
    const handlers = {
        dragenter: (e) => {
            e.preventDefault();
            e.stopPropagation();
            element.classList.add('drag-hover');
        },
        dragover: (e) => {
            e.preventDefault();
            e.stopPropagation();
            element.classList.add('drag-hover');
        },
        dragleave: (e) => {
            e.preventDefault();
            e.stopPropagation();
            // Only remove hover if we're actually leaving the element
            if (!element.contains(e.relatedTarget)) {
                element.classList.remove('drag-hover');
            }
        },
        drop: (e) => {
            e.preventDefault();
            e.stopPropagation();
            element.classList.remove('drag-hover');
            handleDrop(e, index);
        },
        click: (e) => {
            e.preventDefault();
            e.stopPropagation();
            const fileInput = document.getElementById(`file_input_${index}`);
            if (fileInput) {
                fileInput.click();
            }
        }
    };
   
    // Store handlers on element for cleanup
    element._dropHandler = handlers;
   
    // Add all event listeners
    Object.entries(handlers).forEach(([eventName, handler]) => {
        element.addEventListener(eventName, handler, false);
    });
}

// Paste notification
function showPasteNotification(message, type = 'success') {
    const existing = document.querySelector('.paste-notification');
    if (existing) existing.remove();
   
    const notification = document.createElement('div');
    notification.className = `paste-notification ${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check' : type === 'info' ? 'info-circle' : 'exclamation-triangle'}"></i>
        ${message}
    `;
   
    document.body.appendChild(notification);
    setTimeout(() => notification.classList.add('show'), 10);
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 2500);
}

// IOC PROCESSING

// IOC PROCESSING UTILITIES

// Generate HTML for a single IOC item
function generateIOCItemHTML(ioc, index, showFiles) {
    return `
        <div class="ioc-grid-item">
            <input type="hidden" name="iocs[]" value="${ioc}">
            <div class="ioc-grid-header">
                <span class="ioc-index">${index + 1}</span>
                <span class="ioc-grid-ioc" title="${ioc}">${ioc}</span>
            </div>
            ${showFiles ? generateAttachmentZoneHTML(index) : ''}
        </div>
    `;
}

// Generate HTML for attachment zone
function generateAttachmentZoneHTML(index) {
    return `
        <div class="attachment-zone" data-index="${index}">
            <input type="file" id="file_input_${index}" name="attachment_${index}" class="hidden-file-input" multiple onchange="handleFileSelection(this, ${index})">
           
            <div class="drop-area" id="drop-area-${index}">
                <div class="drop-icon">
                    <i class="fas fa-paperclip"></i>
                </div>
                <div class="drop-text">
                    <strong>Click or drag to attach</strong>
                    <span class="drop-subtext">Files, screenshots, or paste (Ctrl+V)</span>
                </div>
                <button type="button" class="browse-btn">
                    <i class="fas fa-folder-open"></i> Browse
                </button>
            </div>
           
            <div class="file-list" id="file-list-${index}" style="display: none;">
                <div class="file-list-header">
                    <span class="file-count-badge" id="file-count-${index}">0 files</span>
                    <button type="button" class="clear-files-btn" onclick="clearFiles(${index})">
                        <i class="fas fa-times"></i> Clear
                    </button>
                </div>
                <div class="file-items" id="file-items-${index}"></div>
               
                <div class="add-more-zone" id="add-more-${index}">
                    <i class="fas fa-plus"></i>
                    <span>Add more files or paste</span>
                </div>
            </div>
        </div>
    `;
}

// Update button state during processing
function updateButtonState(button, isProcessing) {
    if (isProcessing) {
        button.disabled = true;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
    } else {
        button.disabled = false;
        button.innerHTML = button.dataset.originalContent || 'Process IOCs';
    }
}

// Show IOC preview section
function showIOCPreview() {
    const iocPreview = document.getElementById('iocPreview');
    if (iocPreview) {
        iocPreview.style.display = 'block';
        iocPreview.className = 'ioc-preview-modern';
        iocPreview.scrollIntoView({behavior: 'smooth', block: 'nearest'});
    }
}

async function processIOCs(event) {
    const parseResult = await parseAndValidateIOCs();
    if (!parseResult.success) return;
   
    const button = event.target.closest('button');
    button.dataset.originalContent = button.innerHTML;
   
    // Update button state
    updateButtonState(button, true);
   
    const mode = document.querySelector('.mode-option.active').dataset.mode;
    const showFiles = mode === 'threat';
   
    // Reset file storage and tracking
    iocFiles = {};
    fileSignatureTracker = {};
   
    // Generate and display IOC items
    const iocItemsHTML = parseResult.iocs.map((ioc, index) =>
        generateIOCItemHTML(ioc, index, showFiles)
    ).join('');
   
    document.getElementById('iocItems').innerHTML = iocItemsHTML;
   
    // Initialize file handling if needed
    if (showFiles) {
        setTimeout(() => initializeDragAndDrop(), 100);
    }
   
    // Show preview section
    showIOCPreview();
   
    // Restore button state
    updateButtonState(button, false);
}

// Initialize drag and drop
function initializeDragAndDrop() {
    // Initialize clipboard paste support
    initializeClipboardPaste();
   
    // Initialize all attachment zones
    document.querySelectorAll('.attachment-zone').forEach(zone => {
        const index = zone.dataset.index;
        if (index !== undefined && !zone.dataset.initialized) {
            // Mark as initialized to prevent re-initialization
            zone.dataset.initialized = 'true';
           
            // Only initialize the main attachment zone
            initializeDropZone(zone, index);
        }
    });
}

// Initialize clipboard paste
function initializeClipboardPaste() {
    // FIRST: Clean up any existing listeners
    cleanupAllPasteListeners();
    
    // THEN: Add only zone-specific listeners (no global)
    document.querySelectorAll('.attachment-zone').forEach(zone => {
        const index = zone.dataset.index;
        if (index === undefined) return;
       
        zone.setAttribute('tabindex', '0');
       
        // Create single paste handler
        zone._pasteHandler = (e) => {
            e.preventDefault();
            e.stopPropagation();
            handleClipboardPaste(e, index);
        };
       
        // Add listeners
        zone.addEventListener('focus', zoneFocusHandler);
        zone.addEventListener('blur', zoneBlurHandler);
        zone.addEventListener('paste', zone._pasteHandler);
    });
    
    console.log('Initialized clean paste listeners');
}

// Event handlers
function globalPasteHandler(e) {
    const focusedIOC = document.querySelector('.ioc-grid-item:hover, .ioc-grid-item:focus-within');
    if (!focusedIOC) return;
   
    const attachmentZone = focusedIOC.querySelector('.attachment-zone');
    if (!attachmentZone) return;
   
    const index = attachmentZone.dataset.index;
    if (index === undefined) return;
   
    handleClipboardPaste(e, index);
}

function zoneFocusHandler(e) {
    e.target.style.outline = `2px solid ${getComputedStyle(document.documentElement).getPropertyValue('--primary-color')}`;
    e.target.style.outlineOffset = '2px';
}

function zoneBlurHandler(e) {
    e.target.style.outline = 'none';
}

function zonePasteHandler(e, index) {
    e.preventDefault();
    handleClipboardPaste(e, index);
}

// PREVENT DEFAULTS
function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

// RESULTS GENERATION

function generateSingleResultHTML(result) {
    return `
        <div class="message message-success">
            <i class="fas fa-check-circle"></i>
            <div class="success-content">
                <div class="success-info">
                    <span><strong>Success!</strong> ${result.message}</span>
                </div>
            </div>
        </div>
        ${result.copyText ? `
            <div class="copy-section compact">
                <div class="copy-info">
                    <span class="copy-label">Copy:</span>
                    <div class="copy-text" title="${result.copyText}">${result.copyText}</div>
                </div>
                <button class="copy-button" onclick="copyToClipboard('${result.copyText.replace(/'/g, "\\'")}', this)">
                    <i class="fas fa-copy"></i> Copy
                </button>
            </div>
        ` : ''}
    `;
}

function generateBulkResultsHTML(result) {
    const allCopyText = result.results
        .filter(r => r.copyText && r.copyText.trim() !== '')
        .map(r => r.copyText)
        .join('\n');
   
    return `
        <div class="message message-success">
            <i class="fas fa-check-circle"></i>
            <div><strong>Processing Complete!</strong></div>
        </div>
        <table class="results-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>IOC</th>
                    <th>Case Number</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${result.results.map((r, index) => `
                    <tr class="${r.isFailed ? 'failed-row' : r.isExisting ? 'existing-row' : 'success-row'}">
                        <td>${index + 1}</td>
                        <td>
                            <div class="ioc-cell" title="${r.ioc}">${r.ioc}</div>
                        </td>
                        <td>
                            <div class="case-number">${r.caseNumber || '-'}</div>
                        </td>
                        <td>
                            <span class="${r.isSuccess ? 'status-success' : r.isExisting ? 'status-existing' : 'status-failed'}">
                                ${r.isSuccess ? '[OK]' : r.isExisting ? '[INFO]' : '[ERROR]'}
                            </span>
                            ${r.status}
                        </td>
                        <td>
                            ${r.copyText && r.copyText.trim() !== '' ? `
                                <button class="copy-button" onclick="copyToClipboard('individual_${index}', this)">
                                    <i class="fas fa-copy"></i> Copy
                                </button>
                            ` : '<span style="color: var(--text-secondary); font-size: 0.8rem;">-</span>'}
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
        ${allCopyText ? `
            <div class="copy-section copy-all-section">
                <strong>Copy All Results (Excel Ready):</strong>
                <button class="copy-button" onclick="copyToClipboard('all', this)">
                    <i class="fas fa-copy"></i> Copy All Results
                </button>
            </div>
        ` : ''}
        ${result.summary ? `
            <div class="summary-section">
                <h4>Summary:</h4>
                ${result.summary.successful.length > 0 ? `<p style="background: rgba(72, 187, 120, 0.1); color: var(--success-color);">[OK] Successfully created: ${result.summary.successful.length} cases</p>` : ''}
                ${result.summary.existing > 0 ? `<p style="background: rgba(237, 137, 54, 0.1); color: var(--warning-color);">[INFO] Already existing: ${result.summary.existing} cases</p>` : ''}
                ${result.summary.failed.length > 0 ? `<p style="background: rgba(245, 101, 101, 0.1); color: var(--error-color);">[ERROR] Failed: ${result.summary.failed.length} cases</p>` : ''}
            </div>
        ` : ''}
    `;
}

function handleProcessingSuccess(result) {
    copyTexts = {};
   
    // Clear file tracking on success
    iocFiles = {};
    fileSignatureTracker = {};
   
    if (result.isSingle) {
        document.getElementById('processingResult').innerHTML = generateSingleResultHTML(result);
    } else {
        result.results.forEach((r, index) => {
            if (r.copyText && r.copyText.trim() !== '') {
                copyTexts[`individual_${index}`] = r.copyText;
            }
        });
       
        const allCopyText = result.results
            .filter(r => r.copyText && r.copyText.trim() !== '')
            .map(r => r.copyText)
            .join('\n');
       
        if (allCopyText) {
            copyTexts['all'] = allCopyText;
        }
       
        document.getElementById('processingResult').innerHTML = generateBulkResultsHTML(result);
    }
   
    // Reset form
    document.getElementById('ioc_input').value = '';
    document.getElementById('description').value = '';
    document.getElementById('iocPreview').style.display = 'none';
   
    document.getElementById('processingResult').scrollIntoView({behavior: 'smooth', block: 'nearest'});
    showNotification(`Processing completed successfully`, 'success');
}

// FORM SUBMISSION

document.addEventListener('DOMContentLoaded', function() {
    const mainForm = document.getElementById('mainForm');
    if (mainForm) {
        mainForm.addEventListener('submit', async (e) => {
            e.preventDefault();
           
            const formData = new FormData(e.target);
           
            // Remove existing file inputs
            const keys = [...formData.keys()];
            keys.forEach(key => {
                if (key.startsWith('attachment_')) {
                    formData.delete(key);
                }
            });
           
            // Add files from storage
            Object.keys(iocFiles).forEach(index => {
                if (iocFiles[index] && iocFiles[index].length > 0) {
                    iocFiles[index].forEach(file => {
                        formData.append(`attachment_${index}`, file);
                    });
                }
            });
           
            const submitBtn = e.target.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
           
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing Cases...';
           
            const progressDiv = document.createElement('div');
            progressDiv.innerHTML = `
                <div class="message message-info" style=" 1rem;">
                    <i class="fas fa-spinner fa-spin"></i>
                    <div>Processing cases... Please wait.</div>
                </div>
            `;
            document.getElementById('processingResult').innerHTML = '';
            document.getElementById('processingResult').appendChild(progressDiv);
            document.getElementById('processingResult').scrollIntoView({behavior: 'smooth', block: 'nearest'});
           
            try {
                const response = await fetch('/process_cases', {
                    method: 'POST',
                    body: formData
                });
               
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
               
                const result = await response.json();
               
                if (result.success || result.results) {
                    handleProcessingSuccess(result);
                } else {
                    throw new Error(result.message || 'Unknown error occurred');
                }
            } catch (error) {
                console.error('Processing error:', error);
                document.getElementById('processingResult').innerHTML = `
                    <div class="message message-error">
                        <i class="fas fa-exclamation-triangle"></i>
                        <div><strong>Error:</strong> ${error.message}</div>
                    </div>
                `;
                showNotification('Processing failed', 'error');
            }
           
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        });
    }

    // Settings modal click handling
    document.addEventListener('click', function(e) {
        if (e.target.closest('#settingsModal')) {
            console.log('CLICK DETECTED in settings modal:', e.target);
           
            // If it's a button, handle the save
            if (e.target.tagName === 'BUTTON') {
                console.log('BUTTON CLICKED - preventing default');
                e.preventDefault();
               
                // Handle save button
                if (e.target.textContent.includes('Save') || e.target.type === 'submit') {
                    console.log('SAVE BUTTON DETECTED - running save');
                   
                    // Disable button and show loading state
                    const originalText = e.target.innerHTML;
                    e.target.disabled = true;
                    e.target.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
                   
                    const username = document.getElementById('username')?.value || '';
                    const password = document.getElementById('password')?.value || '';
                    const custid = document.getElementById('custid')?.value || '';
                   
                    console.log('Saving values:', {username, password: password ? 'SET' : 'EMPTY', custid});
                   
                    // Save the settings
                    fetch('/api/settings', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({username, password, custid})
                    })
                    .then(r => r.json())
                    .then(result => {
                        console.log('SAVE RESULT:', result);
                       
                        // Restore button state
                        e.target.disabled = false;
                        e.target.innerHTML = originalText;
                       
                        if (result.success) {
                            // Show success notification
                            showNotification('Settings saved successfully!', 'success');
                           
                            // Close the settings modal
                            closeSettings();
                           
                            // Optional: Refresh page to apply new settings
                            setTimeout(() => {
                                console.log('Refreshing page to apply new settings...');
                                window.location.reload();
                            }, 1000);
                        } else {
                            showNotification(result.message || 'Failed to save settings', 'error');
                        }
                    })
                    .catch(err => {
                        console.error('SAVE ERROR:', err);
                       
                        // Restore button state
                        e.target.disabled = false;
                        e.target.innerHTML = originalText;
                       
                        showNotification('Error saving settings: ' + err.message, 'error');
                    });
                }
            }
        }
    });
});

// EVENT HANDLERS

window.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal')) {
        closeSettings();
    }
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        const modal = document.getElementById('settingsModal');
        if (modal && modal.style.display === 'block') {
            closeSettings();
        }
    }
   
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        const modal = document.getElementById('settingsModal');
        if (modal && modal.style.display === 'block') {
            e.preventDefault();
            document.getElementById('settingsForm').dispatchEvent(new Event('submit', { cancelable: true }));
        }
    }
});

window.processIOCs = processIOCs;
