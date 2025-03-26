// General utility functions for the DSSE Tool

// Function to copy text to clipboard
function copyToClipboard(text) {
    // Check if clipboard API is available
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text)
            .then(() => {
                console.log('Text copied to clipboard');
                return true;
            })
            .catch(err => {
                console.error('Could not copy text: ', err);
                return false;
            });
    } else {
        // Fallback for browsers that don't support clipboard API
        const textArea = document.createElement('textarea');
        textArea.value = text;
        
        // Make the textarea out of viewport
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        
        textArea.focus();
        textArea.select();
        
        let success = false;
        try {
            success = document.execCommand('copy');
        } catch (err) {
            console.error('Failed to copy: ', err);
        }
        
        document.body.removeChild(textArea);
        return success;
    }
}

// Show feedback when action is completed
function showActionFeedback(element, successMessage, originalContent, duration = 2000) {
    const originalHTML = element.innerHTML;
    element.innerHTML = successMessage;
    
    setTimeout(() => {
        element.innerHTML = originalHTML || originalContent;
    }, duration);
}

// Initialize tooltips
document.addEventListener('DOMContentLoaded', function() {
    // Initialize any tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Add event listeners for various buttons
    
    // Master key copy button (if exists)
    const masterKeyCopyBtn = document.getElementById('copyMasterKeyBtn');
    if (masterKeyCopyBtn) {
        masterKeyCopyBtn.addEventListener('click', function() {
            const keyElement = document.getElementById('masterKeyDisplay');
            if (keyElement) {
                copyToClipboard(keyElement.value);
                showActionFeedback(this, '<i class="fas fa-check"></i> Copied!', '<i class="fas fa-copy"></i> Copy');
            }
        });
    }
});
