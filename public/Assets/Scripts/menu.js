
document.addEventListener('DOMContentLoaded', () => {
    const linkContextMenu = document.getElementById('linkContextMenu');
    const pageContextMenu = document.getElementById('pageContextMenu');
    const contextMenus = document.querySelectorAll('.custom-context-menu');
    let activeMenu = null; // Track the currently active menu for keyboard navigation
    let menuItems = []; // Track menu items for keyboard navigation
    let currentMenuItemIndex = -1; // Track current selected menu item index

    // --- Configuration Variables ---
    const mobileBreakpoint = 768; // Screen width in pixels to consider as mobile
    const viewportPadding = 10;   // Padding in pixels when adjusting menu position
    const darkThemeToggleKey = 'D'; // Key to press to toggle dark theme (case-insensitive)
    const iconClassName = 'icon-class'; // Class name used for icon elements (can be null or empty string if not used)
    const longPressDuration = 500; // Duration for long press in milliseconds
    // --- End Configuration ---

    // Function to hide all context menus
    function hideContextMenus() {
        contextMenus.forEach(menu => {
            menu.style.display = 'none';
        });
        activeMenu = null;
        menuItems = [];
        currentMenuItemIndex = -1;
    }

    // Function to show context menu at mouse position, with viewport check
    function showContextMenu(menu, event) {
        hideContextMenus(); // Hide any previously shown menus
        menu.style.display = 'block';
        activeMenu = menu;
        menuItems = Array.from(menu.querySelectorAll('[data-action]')); // Get all menu items
        currentMenuItemIndex = -1; // Reset selected index
        focusMenuItem(); // Focus on the first item if available

        const menuWidth = menu.offsetWidth;
        const menuHeight = menu.offsetHeight;
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;

        let menuLeft = event.clientX;
        let menuTop = event.clientY;

        // Check if menu goes off-screen horizontally (right side)
        if (menuLeft + menuWidth > viewportWidth) {
            menuLeft = viewportWidth - menuWidth - viewportPadding; // Adjust to the right edge, with padding
        }
        if (menuLeft < 0) { // Check if menu goes off-screen horizontally (left side)
            menuLeft = viewportPadding; // Adjust to the left edge, with padding
        }

        // Check if menu goes off-screen vertically (bottom side)
        if (menuTop + menuHeight > viewportHeight) {
            menuTop = viewportHeight - menuHeight - viewportPadding; // Adjust to the bottom edge, with padding
        }
        if (menuTop < 0) { // Check if menu goes off-screen vertically (top side)
            menuTop = viewportPadding; // Adjust to the top edge, with padding
        }

        menu.style.left = menuLeft + 'px';
        menu.style.top = menuTop + 'px';
    }

    // Function to show link context menu
    function showLinkMenu(event, targetElement) {
        showContextMenu(linkContextMenu, event);
        linkContextMenu.dataset.linkUrl = targetElement.href || targetElement.src; // Store link URL
    }

    // Function to show page context menu
    function showPageMenu(event) {
        showContextMenu(pageContextMenu, event);
    }

    // Event listener for right-click on the document
    document.addEventListener('contextmenu', function(event) {
        event.preventDefault(); // Prevent default browser context menu
        let targetElement = event.target;
        const isIcon = iconClassName && targetElement.classList.contains(iconClassName); // Check for icon if class name is defined
        if (targetElement.tagName === 'A' || targetElement.tagName === 'IMG' || isIcon) { // Check for link or icon
            showLinkMenu(event, targetElement);
        } else {
            showPageMenu(event);
        }
    });

    // Event listener for left-click on the document to hide menus
    document.addEventListener('click', function(event) {
        if (!event.target.closest('.custom-context-menu')) { // Clicked outside menu
            hideContextMenus(); // Hide context menus if clicked outside
        }
    });

    // Event listener to handle clicks on context menu items
    document.addEventListener('click', function(event) {
        if (event.target.closest('.custom-context-menu')) {
            const action = event.target.dataset.action;
            const linkUrl = linkContextMenu.dataset.linkUrl; // Get the stored link URL

            if (action === 'openNewTab' && linkUrl) {
                window.open(linkUrl, '_blank');
            } else if (action === 'openNewWindow' && linkUrl) {
                window.open(linkUrl, '_blank', 'noopener,noreferrer'); // For security
            } else if (action === 'openCurrentTab' && linkUrl) {
                window.location.href = linkUrl; // Open in the current tab
            }
            else if (action === 'home' || action === 'terms' || action === 'role') {
                // Navigation is already handled by <a> tag in HTML
            }

            hideContextMenus(); // Hide menu after action
        }
    });

    // Dark Theme Toggle (on 'D' key press)
    document.addEventListener('keydown', function(event) {
        if (event.key.toLowerCase() === darkThemeToggleKey.toLowerCase()) { // Case-insensitive key check
            contextMenus.forEach(menu => {
                menu.classList.toggle('dark-theme');
            });
        }
    });


    // --- Touch Support ---
    let touchStartX = 0;
    let touchStartY = 0;
    let touchTimer;

    function clearTouchTimer() {
        clearTimeout(touchTimer);
    }

    function handleLinkTouchStart(event) {
        if (event.touches.length === 1) { // Single touch
            touchStartX = event.touches[0].clientX;
            touchStartY = event.touches[0].clientY;
            touchTimer = setTimeout(() => {
                // Long press detected
                event.preventDefault(); // Prevent default touch behavior
                const targetElement = event.target;
                const isIcon = iconClassName && targetElement.classList.contains(iconClassName);
                if (targetElement.tagName === 'A' || targetElement.tagName === 'IMG' || isIcon) {
                    showLinkMenu(event, targetElement);
                }
            }, longPressDuration);
        }
    }

    function handlePageTouchStart(event) {
        if (event.touches.length === 1) { // Single touch
            touchStartX = event.touches[0].clientX;
            touchStartY = event.touches[0].clientY;
            touchTimer = setTimeout(() => {
                // Long press detected
                event.preventDefault(); // Prevent default touch behavior
                const targetElement = event.target;
                const isIcon = iconClassName && targetElement.classList.contains(iconClassName);
                if (!(targetElement.tagName === 'A' || targetElement.tagName === 'IMG' || isIcon) && !event.target.closest('.custom-context-menu')) {
                    showPageMenu(event);
                }
            }, longPressDuration);
        }
    }


    function handleTouchEnd() {
        clearTouchTimer();
    }

    function handleTouchMove(event) {
        if (event.touches.length > 1) {
            clearTouchTimer(); // Cancel if multi-touch
            return;
        }
        const touchMoveX = event.touches[0].clientX;
        const touchMoveY = event.touches[0].clientY;
        const touchThreshold = 10; // Pixel threshold for swipe detection

        if (Math.abs(touchMoveX - touchStartX) > touchThreshold || Math.abs(touchMoveY - touchStartY) > touchThreshold) {
            clearTouchTimer(); // Cancel if moved too much (swipe)
        }
    }

    const linkTargets = document.querySelectorAll('a, img'); // Add img for image support if needed
    linkTargets.forEach(target => {
        target.addEventListener('touchstart', handleLinkTouchStart);
        target.addEventListener('touchend', handleTouchEnd);
        target.addEventListener('touchmove', handleTouchMove);
        target.addEventListener('touchcancel', handleTouchEnd); // In case touch is interrupted
    });

    document.addEventListener('touchstart', handlePageTouchStart);
    document.addEventListener('touchend', handleTouchEnd);
    document.addEventListener('touchmove', handleTouchMove);
    document.addEventListener('touchcancel', handleTouchEnd);


    // --- Keyboard Navigation ---
    function focusMenuItem() {
        if (menuItems.length > 0) {
            currentMenuItemIndex = 0;
            menuItems[currentMenuItemIndex].focus();
        }
    }

    function navigateMenuItems(direction) {
        if (!activeMenu || menuItems.length === 0) return;

        if (direction === 'down') {
            currentMenuItemIndex++;
            if (currentMenuItemIndex >= menuItems.length) {
                currentMenuItemIndex = 0; // Wrap around to the top
            }
        } else if (direction === 'up') {
            currentMenuItemIndex--;
            if (currentMenuItemIndex < 0) {
                currentMenuItemIndex = menuItems.length - 1; // Wrap around to the bottom
            }
        }

        menuItems[currentMenuItemIndex].focus();
    }


    document.addEventListener('keydown', function(event) {
        if (activeMenu) {
            if (event.key === 'ArrowDown') {
                navigateMenuItems('down');
                event.preventDefault(); // Prevent page scroll
            } else if (event.key === 'ArrowUp') {
                navigateMenuItems('up');
                event.preventDefault(); // Prevent page scroll
            } else if (event.key === 'Enter') {
                if (currentMenuItemIndex !== -1 && menuItems[currentMenuItemIndex]) {
                    menuItems[currentMenuItemIndex].click(); // Simulate click on focused item
                    event.preventDefault();
                }
            } else if (event.key === 'Escape') {
                hideContextMenus(); // Close menu on Escape key
                event.preventDefault();
            }
        }
    });

});