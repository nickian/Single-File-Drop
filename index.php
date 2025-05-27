<?php
// ====================
// CONFIGURATION
// ====================
$SITE_TITLE = 'Single File Drop'; // Site title for branding
$PASSWORD_PROTECTION = true; // Set to true to enable password protection

// SECURITY: Use password_hash('your_password', PASSWORD_DEFAULT) to generate this
// For example on the CLI: php -r 'echo password_hash("your_password", PASSWORD_DEFAULT) . PHP_EOL;'
$PASSWORD_HASH = '$2y$12$L21/aAkgPIP4ioRbqUQSVOgMxpw8mmzpkjSqTEB6//VDXOsUnbwAG'; // Default: "admin"

// File storage configuration
$FILES_DIR = 'files';
$THUMBS_DIR = 'files/thumbs';
$MAX_THUMB_SIZE = 400; // Increased from 200 to 400

// SECURITY: File upload restrictions
$MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1GB max file size
$MAX_TOTAL_UPLOAD_SIZE = 10240 * 1024 * 1024; // 10GB total storage limit
$MAX_ZIP_SIZE = 50 * 1024 * 1024; // 50MB max for zip downloads
$MAX_ZIP_EXTRACTION_SIZE = 100 * 1024 * 1024; // 100MB max when extracted (prevents zip bombs)

// FFMPEG Configuration for Video Thumbnails
$FFMPEG_ENABLED = true; // Set to true to enable video thumbnail generation via FFMPEG
$FFMPEG_PATH = '/usr/bin/ffmpeg'; // Path to the FFMPEG executable

// PDF Thumbnail Configuration
$PDF_THUMB_ENABLED = true; // Set to true to enable PDF thumbnail generation via Imagick

// Deletion Configuration
$ALLOW_FILE_DELETION = true; // Set to false to disable delete buttons and functionality

// SECURITY: Allowed file types (whitelist)
$ALLOWED_EXTENSIONS = [
    'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg',  // Images
    'pdf',                                      // PDFs
    'doc', 'docx', 'txt', 'rtf', 'md',         // Documents
    'xls', 'xlsx', 'csv',                       // Spreadsheets
    'zip', 'rar', '7z',                         // Archives
    'mp3', 'wav', 'ogg', 'm4a',                 // Audio
    'mp4', 'avi', 'mov', 'webm', 'mkv',         // Video
    'json', 'xml', 'html', 'css', 'js', 'log'   // Text files
];

$ALLOWED_MIME_TYPES = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml',
    'application/pdf',
    'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain', 'text/rtf', 'application/rtf', 'text/markdown', 'text/x-markdown',
    'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'text/csv',
    'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed',
    'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp4',
    'video/mp4', 'video/x-msvideo', 'video/quicktime', 'video/webm', 'video/x-matroska',
    'application/json', 'application/xml', 'text/html', 'text/css', 'application/javascript', 'text/x-log'
];

// Preview configuration
$TEXT_PREVIEW_EXTENSIONS = ['txt', 'md', 'json', 'xml', 'log', 'csv', 'html', 'css', 'js'];
$VIDEO_PREVIEW_EXTENSIONS = ['mp4', 'webm', 'mov'];
$AUDIO_PREVIEW_EXTENSIONS = ['mp3', 'wav', 'ogg', 'm4a'];

// SECURITY: Rate limiting configuration
$RATE_LIMIT_WINDOW = 60; // seconds
$RATE_LIMIT_UPLOADS = 10; // max uploads per window
$RATE_LIMIT_ACTIONS = 30; // max actions per window

// ====================
// SECURITY FUNCTIONS
// ====================

session_start();

// SECURITY: Generate CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// SECURITY: Set security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Content-Security-Policy: default-src \'self\'; img-src \'self\' data:; style-src \'self\' \'unsafe-inline\'; script-src \'self\' \'unsafe-inline\'; object-src \'none\'; frame-src \'self\'; media-src \'self\' blob:;');


// SECURITY: Sanitize filename to prevent path traversal
function sanitizeFilename($filename) {
    // 1. Remove any path components
    $raw_basename = basename($filename);

    // 2. Separate extension and name
    $original_extension = strtolower(pathinfo($raw_basename, PATHINFO_EXTENSION));
    $name_part = pathinfo($raw_basename, PATHINFO_FILENAME);

    // 3. Sanitize the name_part:
    //    a. Allow dots in the name_part. (Previously removed all dots)
    //    $name_part = str_replace('.', '', $name_part); // Keep dots for now

    //    b. Replace any characters NOT in the allowed set (alphanumeric, space, common punctuation)
    //       with an underscore.
    //       Allowed: a-z, A-Z, 0-9, space, hyphen, underscore, period, parentheses, square brackets, comma
    $name_part = preg_replace('/[^a-zA-Z0-9 _\\-.()[\]\\,]/', '_', $name_part);
    
    //    c. Consolidate multiple spaces into single spaces.
    $name_part = preg_replace('/\\s+/', ' ', $name_part);

    //    d. Consolidate multiple underscores into single underscores.
    $name_part = preg_replace('/_+/', '_', $name_part);
    
    //    e. Remove leading/trailing underscores and spaces from the name_part.
    $name_part = trim($name_part, '_ ');

    // 4. If name_part became empty after all sanitization (e.g., original name was "..." or just spaces/underscores), provide a default.
    if (empty($name_part)) {
        $name_part = 'file'; // Default name if original name part is entirely removed
    }

    // 5. Reconstruct the filename with the sanitized name_part and original extension.
    $filename = $name_part;
    if (!empty($original_extension)) {
        $filename .= '.' . $original_extension;
    }

    // 6. Apply overall length limit.
    if (strlen($filename) > 255) {
        $current_ext_for_limit = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $current_name_for_limit = pathinfo($filename, PATHINFO_FILENAME);
        
        $ext_length_for_limit = empty($current_ext_for_limit) ? 0 : strlen($current_ext_for_limit) + 1; // +1 for the dot
        $max_name_part_length_for_limit = 255 - $ext_length_for_limit;

        if ($max_name_part_length_for_limit < 1) {
            $safe_name_prefix = substr($current_name_for_limit, 0, 5);
            $remaining_len_for_ext = 255 - (strlen($safe_name_prefix) + 1);
            $truncated_ext = substr($current_ext_for_limit, 0, ($remaining_len_for_ext > 0 ? $remaining_len_for_ext : 0) );
            $filename = $safe_name_prefix . (empty($truncated_ext) ? '' : '.' . $truncated_ext);
            $filename = substr($filename, 0, 255); // Final hard cut
        } else {
            $truncated_name_part = substr($current_name_for_limit, 0, $max_name_part_length_for_limit);
            $filename = $truncated_name_part . (empty($current_ext_for_limit) ? '' : '.' . $current_ext_for_limit);
        }
    }
    
    // Final safety check: if filename somehow ended up empty or just ".ext", provide a sensible default.
    $final_name_part_from_pathinfo = pathinfo($filename, PATHINFO_FILENAME);
    if (empty($final_name_part_from_pathinfo)) {
        $final_extension_from_pathinfo = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $filename = 'file' . (empty($final_extension_from_pathinfo) ? '' : '.' . $final_extension_from_pathinfo);
        if (strlen($filename) > 255) {
            $ext_len_final = empty($final_extension_from_pathinfo) ? 0 : strlen($final_extension_from_pathinfo) + 1;
            $name_part_max_len_final = 255 - $ext_len_final;
            $filename = substr('file', 0, ($name_part_max_len_final > 0 ? $name_part_max_len_final : 0)) 
                      . (empty($final_extension_from_pathinfo) ? '' : '.' . $final_extension_from_pathinfo);
            $filename = substr($filename, 0, 255); 
        }
    }
    if(empty($filename)) { 
        $filename = "sanitized_upload"; 
    }

    return $filename;
}

// SECURITY: Validate CSRF token
function validateCSRF() {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403);
        die(json_encode(['success' => false, 'error' => 'Invalid security token']));
    }
}

// SECURITY: Rate limiting
function rateLimit($action) {
    global $RATE_LIMIT_WINDOW, $RATE_LIMIT_UPLOADS, $RATE_LIMIT_ACTIONS;
    
    $key = 'rate_' . $action . '_' . $_SERVER['REMOTE_ADDR'];
    $now = time();
    
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = ['count' => 0, 'window_start' => $now];
    }
    
    // Reset window if expired
    if ($now - $_SESSION[$key]['window_start'] > $RATE_LIMIT_WINDOW) {
        $_SESSION[$key] = ['count' => 1, 'window_start' => $now];
        return true;
    }
    
    $_SESSION[$key]['count']++;
    
    $limit = ($action === 'upload') ? $RATE_LIMIT_UPLOADS : $RATE_LIMIT_ACTIONS;
    
    if ($_SESSION[$key]['count'] > $limit) {
        http_response_code(429);
        die(json_encode(['success' => false, 'error' => 'Rate limit exceeded. Please try again later.']));
    }
    
    return true;
}

// SECURITY: Validate file type
function validateFileType($filename, $tmpFile) {
    global $ALLOWED_EXTENSIONS, $ALLOWED_MIME_TYPES;
    
    // Check extension
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    if (!in_array($ext, $ALLOWED_EXTENSIONS)) {
        return "File extension '$ext' is not allowed.";
    }
    
    // Check MIME type
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $tmpFile);
        finfo_close($finfo);
        
        if (!in_array($mimeType, $ALLOWED_MIME_TYPES)) {
            if ($mimeType === 'application/octet-stream') {
                $genericAllowedExt = ['zip', 'rar', '7z', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']; 
                if (!in_array($ext, $genericAllowedExt)) {
                    error_log("MIME type mismatch for extension .$ext: detected $mimeType (generic), not specifically allowed for this extension type.");
                    return "File type ($mimeType for .$ext) is not allowed due to MIME type mismatch (generic type not permitted for this extension).";
                }
                // If it is an allowed generic octet-stream, we let it pass for now, relying on extension.
            } else {
                error_log("MIME type mismatch for extension .$ext: detected $mimeType, not in allowed list: " . implode(', ', $ALLOWED_MIME_TYPES));
                return "File type ($mimeType for .$ext) is not allowed due to server MIME type policy.";
            }
        }
    } else {
        error_log("finfo_open function not available. MIME type validation is less secure. Relying on extension only for file: " . $filename);
        // If finfo is not available, we can't perform robust MIME check. 
        // For security, one might choose to reject or be more cautious. 
        // Current behavior: falls through, relying on extension & PHP content check.
    }
    
    // Additional check for PHP files
    $content = @file_get_contents($tmpFile, false, null, 0, 1024); // Read first 1KB for broader check
    if ($content !== false && preg_match('/^(<\?php|<\?=|<\?|\\b(eval|system|exec|passthru|shell_exec|proc_open|popen)\s*\\()/i', $content)) {
        error_log("Potential PHP or shell execution content detected in file: " . $filename);
        return "File appears to contain prohibited script content.";
    }
    
    return true; // File is valid
}

// SECURITY: Check disk space to prevent DoS
function checkDiskSpace($size) {
    global $FILES_DIR, $MAX_TOTAL_UPLOAD_SIZE;
    
    $totalSize = 0;
    if (is_dir($FILES_DIR)) {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($FILES_DIR, RecursiveDirectoryIterator::SKIP_DOTS)
        );
        foreach ($files as $file) {
            if ($file->isFile()) {
                $totalSize += $file->getSize();
            }
        }
    }
    
    return ($totalSize + $size) <= $MAX_TOTAL_UPLOAD_SIZE;
}

// SECURITY: Create .htaccess to prevent PHP execution
function createHtaccessInDirectory($directoryPath) {
    // Ensure the path is within the main files directory for safety, though this function
    // should ideally be called with already validated paths.
    global $FILES_DIR;
    $realBaseFilesDir = realpath($FILES_DIR);
    // realpath() returns false if the path does not exist. We might be creating it.
    // So, construct the prospective real path and check its prefix.
    $prospectiveRealPath = $realBaseFilesDir . DIRECTORY_SEPARATOR . str_replace($realBaseFilesDir, '', $directoryPath);
    $prospectiveRealPath = str_replace(DIRECTORY_SEPARATOR . DIRECTORY_SEPARATOR, DIRECTORY_SEPARATOR, $prospectiveRealPath); // Normalize separators

    // A more direct check if $directoryPath is already absolute and resolved:
    if (strpos(realpath($directoryPath), $realBaseFilesDir) !== 0 && realpath($directoryPath) !== $realBaseFilesDir) {
         // If $directoryPath hasn't been created yet, realpath will fail. 
         // This check is more for post-creation validation or if path is assumed to exist.
         // For pre-creation, ensure $directoryPath is constructed safely from $FILES_DIR
    }

    $htaccess = rtrim($directoryPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.htaccess';
    if (!file_exists($htaccess)) {
        $content = "# Prevent PHP execution\n";
        $content .= "<FilesMatch \"\\.(php|phtml|php3|php4|php5|pl|py|jsp|asp|htm|shtml|sh|cgi)$\">\n";
        $content .= "    SetHandler text/plain\n";
        $content .= "</FilesMatch>\n";
        $content .= "Options -ExecCGI -Indexes\n";
        $content .= "<Files .htaccess>\n";
        $content .= "    Order allow,deny\n";
        $content .= "    Deny from all\n";
        $content .= "</Files>\n";
        @file_put_contents($htaccess, $content);
    }
}

// Helper to create index.html in a directory to prevent listing
function createIndexHtmlInDirectory($directoryPath) {
    // Similar safety checks as createHtaccessInDirectory might be useful if called directly with untrusted paths
    // but ensureSecurePath should handle path construction safely.
    $indexFile = rtrim($directoryPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'index.html';
    if (!file_exists($indexFile)) {
        @file_put_contents($indexFile, '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1></body></html>');
    }
}

// Function to recursively create and secure directories
function ensureSecurePath($baseDir, $relativePath) {
    global $FILES_DIR; // To check if we are creating within $FILES_DIR for .htaccess
    $fullPath = rtrim($baseDir, DIRECTORY_SEPARATOR);

    // Normalize relativePath, remove leading/trailing slashes, replace backslashes
    $relativePath = trim(str_replace('\\', '/', $relativePath), '/');

    if (!empty($relativePath)) {
        $segments = explode('/', $relativePath);
    } else {
        $segments = [];
    }

    $currentPathAbs = $fullPath; // Start with the base directory absolute path

    // First, ensure the base directory itself exists.
    if (!is_dir($currentPathAbs)) {
        if (!@mkdir($currentPathAbs, 0755, true)) {
            error_log("Failed to create base directory: " . $currentPathAbs);
            return false;
        }
        // Secure the base $FILES_DIR itself if it was just created and $baseDir is $FILES_DIR
        if (realpath($currentPathAbs) === realpath($FILES_DIR)) { 
            createHtaccessInDirectory($currentPathAbs);
            createIndexHtmlInDirectory($currentPathAbs);
        }
    }

    // Iterate through segments of the relative path
    foreach ($segments as $segment) {
        if (empty($segment) || $segment === '.' || $segment === '..') { // Basic sanitization for segments
            error_log("Invalid segment in path creation: " . $segment);
            return false; // Disallow dangerous segments
        }
        $currentPathAbs .= DIRECTORY_SEPARATOR . $segment;
        if (!is_dir($currentPathAbs)) {
            if (!@mkdir($currentPathAbs, 0755)) { // Create one segment at a time, not recursive here
                error_log("Failed to create subdirectory: " . $currentPathAbs);
                return false; 
            }
            // Secure newly created subdirectory if it's within $FILES_DIR
            $realCurrentPathAbs = realpath($currentPathAbs);
            $realBaseFilesDir = realpath($FILES_DIR);
            if ($realCurrentPathAbs !== false && $realBaseFilesDir !== false && strpos($realCurrentPathAbs, $realBaseFilesDir) === 0) {
                 createHtaccessInDirectory($currentPathAbs);
                 createIndexHtmlInDirectory($currentPathAbs);
            }
        }
    }
    return realpath($fullPath . (empty($segments) ? '' : DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $segments)));
}

// Recursive function to delete a directory and its contents
function deleteDirectoryRecursive($dirPath) {
    global $FILES_DIR, $THUMBS_DIR; // For path validation
    $realBaseFilesDir = realpath($FILES_DIR);
    $realDirPath = realpath($dirPath);

    // Security: Ensure we are within $FILES_DIR or $THUMBS_DIR
    $isValidPath = false;
    if ($realBaseFilesDir && $realDirPath && strpos($realDirPath, $realBaseFilesDir) === 0) {
        $isValidPath = true;
    }
    if (!$isValidPath) {
        $realBaseThumbsDir = realpath($THUMBS_DIR);
        if ($realBaseThumbsDir && $realDirPath && strpos($realDirPath, $realBaseThumbsDir) === 0) {
            $isValidPath = true;
        }
    }

    if (!$isValidPath || $realDirPath === $realBaseFilesDir || $realDirPath === realpath($THUMBS_DIR)) {
        error_log("Attempt to delete invalid or root directory: " . $dirPath . " (Resolved: " . $realDirPath . ")");
        return false; // Do not delete the root files/thumbs directory itself
    }

    if (!is_readable($dirPath)) { // Check if readable before scandir
        error_log("Directory not readable, cannot delete: " . $dirPath);
        return false;
    }

    $items = scandir($dirPath);
    if ($items === false) {
        error_log("Failed to scan directory for deletion: " . $dirPath);
        return false;
    }

    foreach ($items as $item) {
        if ($item == '.' || $item == '..') {
            continue;
        }
        $path = $dirPath . DIRECTORY_SEPARATOR . $item;
        if (is_dir($path)) {
            if (!deleteDirectoryRecursive($path)) {
                return false; // Stop if a subdirectory deletion fails
            }
        } else {
            if (!@unlink($path)) {
                error_log("Failed to delete file: " . $path);
                return false; // Stop if a file deletion fails
            }
        }
    }
    if (!@rmdir($dirPath)) {
        error_log("Failed to remove directory: " . $dirPath);
        return false;
    }
    return true;
}

// Initialize directories with security
if (!file_exists($FILES_DIR)) {
    ensureSecurePath($FILES_DIR, ''); 
}
if (!file_exists($THUMBS_DIR)) {
    if (@mkdir($THUMBS_DIR, 0755, true)) {
        createIndexHtmlInDirectory($THUMBS_DIR); 
    }
}

// This original loop for index.html is largely covered by ensureSecurePath and the direct THUMBS_DIR init.
// Keeping it commented out as it might be redundant or conflict.
/*
foreach ([$FILES_DIR, $THUMBS_DIR] as $dir) {
    if (is_dir($dir)) { 
        createIndexHtmlInDirectory($dir);
    }
}
*/

// Handle authentication
if ($PASSWORD_PROTECTION && !isset($_SESSION['authenticated'])) {
    if (isset($_POST['password'])) {
        if (password_verify($_POST['password'], $PASSWORD_HASH)) {
            session_regenerate_id(true); // Prevent session fixation
            $_SESSION['authenticated'] = true;
        } else {
            // Log failed login attempt
            error_log('Failed login attempt from IP: ' . $_SERVER['REMOTE_ADDR']);
        }
    } elseif (!isset($_POST['action']) || $_POST['action'] !== 'login') {
        showLoginForm();
        exit;
    }
}

// Handle AJAX requests
if (isset($_POST['action'])) {
    header('Content-Type: application/json');
    
    // SECURITY: Validate CSRF for all actions except login
    if ($_POST['action'] !== 'login') {
        validateCSRF();
    }
    
    // SECURITY: Apply rate limiting
    rateLimit($_POST['action']);
    
    switch ($_POST['action']) {
        case 'upload':
            handleUpload();
            break;
        case 'delete':
            handleDelete();
            break;
        case 'list':
            handleList();
            break;
        case 'preview_text':
            handleTextPreview();
            break;
        case 'zip_contents':
            handleZipContents();
            break;
        case 'get_storage_usage': // New action
            handleGetStorageUsage();
            break;
        case 'download_selected_zip': // New action for selected download
            handleDownloadSelectedZip();
            break;
        case 'logout': // New action for logout
            if (session_status() == PHP_SESSION_ACTIVE) {
                session_destroy();
            }
            $_SESSION = []; // Clear session array
            // Optionally, also delete session cookie if needed, though destroy usually handles it.
            // if (ini_get(\"session.use_cookies\")) {
            //     $params = session_get_cookie_params();
            //     setcookie(session_name(), \'\', time() - 42000,
            //         $params[\"path\"], $params[\"domain\"],
            //         $params[\"secure\"], $params[\"httponly\"]
            //     );
            // }
            echo json_encode(['success' => true]);
            break;
        case 'create_folder': // New action for creating a folder
            handleCreateFolder();
            break;
        case 'rename': // New action for renaming
            handleRename();
            break;
        case 'login':
            if ($PASSWORD_PROTECTION && password_verify($_POST['password'], $PASSWORD_HASH)) {
                session_regenerate_id(true);
                $_SESSION['authenticated'] = true;
                echo json_encode(['success' => true, 'csrf_token' => $_SESSION['csrf_token']]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Invalid password']);
            }
            break;
    }
    exit;
}

// Handle download all
if (isset($_GET['download_all'])) {
    if (!$PASSWORD_PROTECTION || isset($_SESSION['authenticated'])) {
        downloadAll();
    } else {
        http_response_code(403);
        die('Authentication required.');
    }
    exit;
}

// Handle single file download
if (isset($_GET['download'])) {
     if (!$PASSWORD_PROTECTION || isset($_SESSION['authenticated'])) {
        downloadSingle($_GET['download']);
    } else {
        http_response_code(403);
        die('Authentication required.');
    }
    exit;
}

// Function to show login form
function showLoginForm() {
    global $SITE_TITLE;
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - <?php echo htmlspecialchars($SITE_TITLE); ?></title>
    <style>
        /* Add CSS Variable definitions directly for the login page */
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f5f5f5;
            --bg-tertiary: #e0e0e0;
            --text-primary: #333333;
            --text-secondary: #666666;
            --border-color: #dddddd;
            --accent-color: #367e39; /* Keep your existing accent color */
            --danger-color: #f44336;
            --shadow: rgba(0, 0, 0, 0.1);
        }
        
        [data-theme="dark"] {
            --bg-primary: #1e1e1e;
            --bg-secondary: #2d2d2d;
            --bg-tertiary: #3d3d3d;
            --text-primary: #ffffff;
            --text-secondary: #b0b0b0;
            --border-color: #444444;
            /* --accent-color: #66bb6a; /* Optional: different accent for dark mode */
            --danger-color: #ef5350;
            --shadow: rgba(0, 0, 0, 0.3);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: var(--bg-secondary); /* Use CSS Variable */
            color: var(--text-primary);    /* Use CSS Variable */
            transition: background-color 0.3s, color 0.3s; /* Add transition */
        }
        .login-form {
            background: var(--bg-primary); /* Use CSS Variable */
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px var(--shadow); /* Use CSS Variable */
            width: 100%;
            max-width: 400px;
        }
        .login-form h2 {
            margin-bottom: 1.5rem;
            color: var(--text-primary); /* Use CSS Variable */
        }
        .login-form input {
            width: 100%;
            padding: 0.75rem;
            font-size: 1rem;
            border: 1px solid var(--border-color); /* Use CSS Variable */
            border-radius: 5px;
            margin-bottom: 1rem;
            background-color: var(--bg-secondary); /* Input background */
            color: var(--text-primary); /* Input text color */
        }
        .login-form input::placeholder {
            color: var(--text-secondary);
        }
        .login-form button {
            width: 100%;
            padding: 0.75rem;
            font-size: 1rem;
            background: var(--accent-color); /* Use CSS Variable */
            color: white; /* Keep white for contrast on accent */
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.3s; /* Add transition for hover */
        }
        .login-form button:hover {
            /* A slightly darker/lighter version of accent could be a CSS var too if needed */
            /* For simplicity, using a filter or a fixed darker shade */
            filter: brightness(90%);
        }
        .error {
            color: var(--danger-color); /* Use CSS variable */
            margin-bottom: 1rem;
            display: none;
        }
    </style>
</head>
<body>
    <div class="login-form">
        <h2>Login Required</h2>
        <div class="error" id="error"></div>
        <form id="loginForm">
            <input type="password" id="password" placeholder="Enter password" required autocomplete="current-password">
            <button type="submit">Login</button>
        </form>
    </div>
    <script>
        // Apply OS theme preference on login page load
        function applyLoginTheme() {
            if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                document.documentElement.setAttribute('data-theme', 'dark');
            } else {
                document.documentElement.setAttribute('data-theme', 'light');
            }
        }
        applyLoginTheme(); // Apply on initial load

        // Optional: Listen for OS theme changes while the login page is open
        if (window.matchMedia) {
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyLoginTheme);
        }

        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = document.getElementById('password').value;
            const response = await fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=login&password=${encodeURIComponent(password)}`
            });
            const result = await response.json();
            if (result.success) {
                window.location.reload();
            } else {
                document.getElementById('error').style.display = 'block';
                document.getElementById('error').textContent = result.error || 'Login failed.';
            }
        });
    </script>
</body>
</html>
    <?php
}

// Function to handle file upload
function handleUpload() {
    global $FILES_DIR, $THUMBS_DIR, $MAX_THUMB_SIZE, $MAX_FILE_SIZE, 
           $FFMPEG_ENABLED, $FFMPEG_PATH, $VIDEO_PREVIEW_EXTENSIONS, 
           $PDF_THUMB_ENABLED;
    
    $uiCurrentPathInput = $_POST['currentDirectoryPath'] ?? ''; // Path from UI navigation
    $fileIntendedSubPathInput = $_POST['intendedSubPath'] ?? '';    // Path from dropped folder structure or just filename

    // --- Path Sanitization and Combination --- 
    $baseFilesDirReal = realpath($FILES_DIR);
    if ($baseFilesDirReal === false) {
        echo json_encode(['success' => false, 'error' => 'Server configuration error: Invalid FILES_DIR']); return;
    }

    // 1. Sanitize uiCurrentPathInput (path active in UI)
    $sanitizedUiPath = '';
    if ($uiCurrentPathInput !== '') {
        $normalizedUiPath = trim(str_replace('\\', '/', $uiCurrentPathInput), '/');
        if (strpos($normalizedUiPath, '..') === false) {
            $prospectiveUiPath = $baseFilesDirReal . DIRECTORY_SEPARATOR . $normalizedUiPath;
            if (realpath($prospectiveUiPath) !== false && strpos(realpath($prospectiveUiPath), $baseFilesDirReal) === 0) {
                $sanitizedUiPath = $normalizedUiPath;
            }
        }
    }

    // 2. Sanitize fileIntendedSubPathInput (path from dropped item, relative to itself or just filename)
    // This path might contain subdirectories if a folder was dropped.
    $sanitizedFileSubPath = '';
    $actualFileName = pathinfo($fileIntendedSubPathInput, PATHINFO_BASENAME);
    $intendedDirStructureWithinFile = pathinfo($fileIntendedSubPathInput, PATHINFO_DIRNAME);

    if ($intendedDirStructureWithinFile === '.' || $intendedDirStructureWithinFile === '/') {
        $intendedDirStructureWithinFile = '';
    }
    if ($intendedDirStructureWithinFile !== '') {
         $normalizedIntendedDir = trim(str_replace('\\', '/', $intendedDirStructureWithinFile), '/');
         if (strpos($normalizedIntendedDir, '..') === false) {
             $sanitizedFileSubPath = $normalizedIntendedDir;
         }
    }
    // If fileIntendedSubPathInput was just a filename, $sanitizedFileSubPath remains ''

    // 3. Combine paths: UI path + path from dropped folder structure
    $finalTargetSubDirRelative = $sanitizedUiPath;
    if (!empty($sanitizedFileSubPath)) {
        $finalTargetSubDirRelative = ($finalTargetSubDirRelative ? $finalTargetSubDirRelative . '/' : '') . $sanitizedFileSubPath;
    }
    $finalTargetSubDirRelative = trim($finalTargetSubDirRelative, '/');

    // Ensure the target upload directory exists and is secure
    $finalUploadDirPathAbsolute = ensureSecurePath($FILES_DIR, $finalTargetSubDirRelative);
    if ($finalUploadDirPathAbsolute === false) {
        echo json_encode(['success' => false, 'error' => 'Failed to create or secure upload subdirectory for the file.']);
        return;
    }
    // --- End Path Sanitization and Combination ---

    if (!isset($_FILES['file'])) {
        echo json_encode(['success' => false, 'error' => 'No file uploaded']);
        return;
    }
    
    $file = $_FILES['file'];
    
    // SECURITY: Check file size (remains important)
    if ($file['size'] > $MAX_FILE_SIZE) {
        echo json_encode(['success' => false, 'error' => 'File too large. Maximum size is ' . ($MAX_FILE_SIZE / 1024 / 1024) . 'MB']);
        return;
    }
    
    // SECURITY: Check if we have disk space (remains important)
    if (!checkDiskSpace($file['size'])) {
        echo json_encode(['success' => false, 'error' => 'Storage limit exceeded']);
        return;
    }
    
    // Use the BASENAME from intendedSubPath for the actual filename part
    $fileNameFromClient = sanitizeFilename($actualFileName); 
    if (empty($fileNameFromClient)) {
        echo json_encode(['success' => false, 'error' => 'Invalid filename after sanitization.']);
        return;
    }
    
    // SECURITY: Validate file type 
    $validationResult = validateFileType($fileNameFromClient, $file['tmp_name']);
    if ($validationResult !== true) {
        echo json_encode(['success' => false, 'error' => $validationResult]);
        return;
    }
    
    $targetPath = $finalUploadDirPathAbsolute . DIRECTORY_SEPARATOR . $fileNameFromClient;
    $overwriteAction = $_POST['overwrite_action'] ?? null;
    $userSuggestedNameInput = $_POST['userSuggestedName'] ?? null;

    // Check for file existence if no overwrite action is specified yet
    if (!$overwriteAction && file_exists($targetPath)) {
        echo json_encode([
            'success' => 'conflict', 
            'filename' => $fileNameFromClient, 
            'message' => "File '{$fileNameFromClient}' already exists in the target directory ('{$finalTargetSubDirRelative}').",
            // We need to send back enough info for the client to re-initiate if needed.
            // However, sending back tmp_name is not ideal for security/state if we were to hold it.
            // The re-upload strategy means client just needs the filename and original context.
        ]);
        return;
    }

    $fileName = $fileNameFromClient; // Initialize $fileName with the client-provided (and sanitized) name

    // Handle renaming or use user-suggested name
    if ($overwriteAction === 'rename') {
        $baseNameToRename = $fileNameFromClient; // Default to original filename for renaming
        if ($userSuggestedNameInput !== null && trim($userSuggestedNameInput) !== '') {
            // Sanitize userSuggestedNameInput like a filename (no paths, just the name part)
            $sanitizedUserSuggestion = sanitizeFilename(basename(trim($userSuggestedNameInput))); 
            if (!empty($sanitizedUserSuggestion)) {
                $baseNameToRename = $sanitizedUserSuggestion;
            }
        }
        
        $counter = 1;
        $originalNameForLoop = $baseNameToRename; 
        $info = pathinfo($originalNameForLoop);
        $fileName = $info['filename'] . '_' . $counter . (isset($info['extension']) ? '.' . $info['extension'] : '');
        $targetPath = $finalUploadDirPathAbsolute . DIRECTORY_SEPARATOR . $fileName;
        while (file_exists($targetPath)) {
            $counter++;
            $fileName = $info['filename'] . '_' . $counter . (isset($info['extension']) ? '.' . $info['extension'] : '');
            $targetPath = $finalUploadDirPathAbsolute . DIRECTORY_SEPARATOR . $fileName;
        }
    } elseif ($overwriteAction === 'replace') {
        // $targetPath is already $finalUploadDirPathAbsolute . DIRECTORY_SEPARATOR . $fileNameFromClient;
        // $fileName is $fileNameFromClient by default initialization.
    } else if (!$overwriteAction && file_exists($targetPath)) {
        // This case should have been caught by the 'conflict' response.
        // If somehow reached, this is implicit rename (original behavior for non-conflict-aware client)
        // For safety, log it if it happens.
        error_log("Warning: Reached implicit renaming fallback in handleUpload for existing file: " . $targetPath);
        $counter = 1;
        $originalNameForLoop = $fileNameFromClient;
        $info = pathinfo($originalNameForLoop);
        $fileName = $info['filename'] . '_' . $counter . (isset($info['extension']) ? '.' . $info['extension'] : '');
        $targetPath = $finalUploadDirPathAbsolute . DIRECTORY_SEPARATOR . $fileName;
        while (file_exists($targetPath)) {
            $counter++;
            $fileName = $info['filename'] . '_' . $counter . (isset($info['extension']) ? '.' . $info['extension'] : '');
            $targetPath = $finalUploadDirPathAbsolute . DIRECTORY_SEPARATOR . $fileName;
        }
    } else {
        // No conflict and no specific action: $targetPath is already correct using $fileNameFromClient
        // $fileName is also $fileNameFromClient
    }
    // Ensure $targetPath is correctly set if it wasn't in a rename loop
    if ($overwriteAction !== 'rename') {
         $targetPath = $finalUploadDirPathAbsolute . DIRECTORY_SEPARATOR . $fileName; 
    }

    
    if (move_uploaded_file($file['tmp_name'], $targetPath)) {
        // Create thumbnail if it's an image or a video with FFMPEG enabled
        $imageTypes = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
        $ext = strtolower(pathinfo($targetPath, PATHINFO_EXTENSION));
        
        $canCreateThumb = false;
        if (in_array($ext, $imageTypes) && function_exists('gd_info')) {
            $canCreateThumb = true;
        } elseif ($FFMPEG_ENABLED && in_array($ext, $VIDEO_PREVIEW_EXTENSIONS) && is_executable($FFMPEG_PATH)) {
            $canCreateThumb = true;
        } elseif ($PDF_THUMB_ENABLED && $ext === 'pdf' && class_exists('Imagick')) {
            $canCreateThumb = true;
        }
        
        if ($canCreateThumb) {
            // Construct the path for the thumbnail, mirroring the subdirectory structure
            // $finalTargetSubDirRelative is path like "ui_folder/dropped_folder_subpath"
            $thumbDestinationDirAbsolute = ensureSecurePath($THUMBS_DIR, $finalTargetSubDirRelative);
            if($thumbDestinationDirAbsolute === false){
                 error_log("Failed to create or secure thumbnail subdirectory: " . $THUMBS_DIR . DIRECTORY_SEPARATOR . $finalTargetSubDirRelative);
            } else {
                 // The actual thumbnail filename (e.g., image.jpg or video.mp4.jpg)
                $thumbName = $fileName; // Use the (potentially renamed) filename from $targetPath
                $fileExtForThumb = strtolower(pathinfo($fileName, PATHINFO_EXTENSION)); // Get ext from final sanitized filename

                if (in_array($fileExtForThumb, $VIDEO_PREVIEW_EXTENSIONS) || ($fileExtForThumb === 'pdf' && $PDF_THUMB_ENABLED && class_exists('Imagick'))) {
                     $thumbName .= '.jpg';
                }
                $thumbFinalPath = $thumbDestinationDirAbsolute . DIRECTORY_SEPARATOR . $thumbName;
                createThumbnail($targetPath, $thumbFinalPath); 
            }
        }
        
        // Return the filename and its relative path for UI update if needed
        $fileLocationForUI = ($finalTargetSubDirRelative ? $finalTargetSubDirRelative . '/' : '') . $fileName;
        echo json_encode(['success' => true, 'filename' => $fileName, 'path' => $finalTargetSubDirRelative, 'fullPathForUI' => $fileLocationForUI]);
    } else {
        error_log("Failed to move uploaded file: " . $file['name'] . " to " . $targetPath . " - PHP Error: " . $file['error']);
        echo json_encode(['success' => false, 'error' => 'Failed to upload file. Check server logs.']);
    }
}

// Function to create thumbnail
function createThumbnail($source, $destination) {
    global $MAX_THUMB_SIZE, $FFMPEG_ENABLED, $FFMPEG_PATH, $VIDEO_PREVIEW_EXTENSIONS, 
           $PDF_THUMB_ENABLED;
    
    $sourceExt = strtolower(pathinfo($source, PATHINFO_EXTENSION));

    // Try Imagick for PDF Thumbnails first
    if ($PDF_THUMB_ENABLED && $sourceExt === 'pdf' && class_exists('Imagick')) {
        try {
            $thumbFilename = basename($source) . '.jpg';
            $pdfThumbDestination = dirname($destination) . '/' . $thumbFilename;

            $imagick = new Imagick();
            $imagick->setResolution(150, 150); // Set resolution before reading PDF page
            $imagick->readImage($source . '[0]'); // Read the first page
            $imagick->setImageFormat('jpeg');
            $imagick->setImageCompressionQuality(85);
            
            // Resize to fit within MAX_THUMB_SIZE, maintaining aspect ratio
            $imagick->thumbnailImage($MAX_THUMB_SIZE, $MAX_THUMB_SIZE, true, true);
            
            if ($imagick->writeImage($pdfThumbDestination)) {
                error_log("Imagick PDF thumbnail created for $source at $pdfThumbDestination");
                $imagick->clear();
                $imagick->destroy();
                return true;
            } else {
                error_log("Imagick failed to write PDF thumbnail for $source to $pdfThumbDestination");
            }
            $imagick->clear();
            $imagick->destroy();
        } catch (Exception $e) {
            error_log("Imagick PDF thumbnail creation failed for $source: " . $e->getMessage());
        }
        return false; // Fall through if Imagick failed
    }

    // Try FFMPEG for videos
    if ($FFMPEG_ENABLED && in_array($sourceExt, $VIDEO_PREVIEW_EXTENSIONS)) {
        if (!is_executable($FFMPEG_PATH)) {
            error_log("FFMPEG path ($FFMPEG_PATH) is not executable or FFMPEG is not installed.");
            return false;
        }
        
        // Create a .jpg filename for the video thumbnail
        $thumbFilename = basename($source) . '.jpg';
        $ffmpegThumbDestination = dirname($destination) . '/' . $thumbFilename;

        // Ensure the destination directory exists
        $thumbDir = dirname($ffmpegThumbDestination);
        if (!is_dir($thumbDir)) {
            if (!mkdir($thumbDir, 0755, true)) {
                error_log("Failed to create thumbnail directory: $thumbDir");
                return false;
            }
        }

        $escapedFfmpegThumbDestination = escapeshellarg($ffmpegThumbDestination);
        $sourceArg = escapeshellarg($source);
        
        // Command to extract one frame at 1s, scale to $MAX_THUMB_SIZE height, maintaining aspect ratio
        // Outputting as JPG to the new .jpg filename
        $command = $FFMPEG_PATH . " -i " . $sourceArg . " -ss 00:00:01.000 -vframes 1 -vf \"scale=-1:" . $MAX_THUMB_SIZE . ":force_original_aspect_ratio=decrease\" -y -f image2 " . $escapedFfmpegThumbDestination . " 2>&1";
        
        $ffmpegOutput = @shell_exec($command); 

        if (file_exists($ffmpegThumbDestination) && filesize($ffmpegThumbDestination) > 0) {
            // Check if output is a valid image (simple check)
            if (@getimagesize($ffmpegThumbDestination)) {
                 error_log("FFMPEG thumbnail created for $source at $ffmpegThumbDestination");
                return true;
            } else {
                error_log("FFMPEG created an invalid or empty thumbnail for $source at $ffmpegThumbDestination. Output: " . ($ffmpegOutput ?? 'No output'));
                if(file_exists($ffmpegThumbDestination)) unlink($ffmpegThumbDestination); // Clean up invalid file
                return false;
            }
        } else {
            error_log("FFMPEG failed to create thumbnail for $source. Command: $command. Output: " . ($ffmpegOutput ?? 'No output'));
            return false;
        }
    }

    // Fallback to GD for images if not a video or FFMPEG failed/disabled
    // For actual images, the $destination is already correct (e.g., files/thumbs/image.jpg)
    if (!function_exists('gd_info')) {
        error_log("GD library not available for image thumbnail creation.");
        return false;
    }

    try {
        $info = getimagesize($source);
        if (!$info) return false;
        
        $type = $info[2];
        $image = null;
        switch ($type) {
            case IMAGETYPE_JPEG:
                $image = @imagecreatefromjpeg($source);
                break;
            case IMAGETYPE_PNG:
                $image = @imagecreatefrompng($source);
                break;
            case IMAGETYPE_GIF:
                $image = @imagecreatefromgif($source);
                break;
            case IMAGETYPE_WEBP:
                 if (function_exists('imagecreatefromwebp')) {
                    $image = @imagecreatefromwebp($source);
                } else {
                    error_log("WEBP support not enabled in GD for thumbnail: $source");
                    return false;
                }
                break;
            default:
                return false;
        }
        
        if (!$image) {
            error_log("Failed to create image from source for thumbnail: $source, type: $type");
            return false;
        }
        
        $width = imagesx($image);
        $height = imagesy($image);
        
        // Calculate new dimensions
        if ($width > $height) {
            $newWidth = $MAX_THUMB_SIZE;
            $newHeight = floor($height * ($MAX_THUMB_SIZE / $width));
        } else {
            $newHeight = $MAX_THUMB_SIZE;
            $newWidth = floor($width * ($MAX_THUMB_SIZE / $height));
        }
        
        // Create thumbnail
        $thumb = imagecreatetruecolor($newWidth, $newHeight);
        
        // Preserve transparency for PNG and GIF
        if ($type == IMAGETYPE_PNG || $type == IMAGETYPE_GIF) {
            imagecolortransparent($thumb, imagecolorallocatealpha($thumb, 0, 0, 0, 127));
            imagealphablending($thumb, false);
            imagesavealpha($thumb, true);
        }
        
        imagecopyresampled($thumb, $image, 0, 0, 0, 0, $newWidth, $newHeight, $width, $height);
        
        // Save thumbnail
        $success = false;
        switch ($type) {
            case IMAGETYPE_JPEG:
                $success = imagejpeg($thumb, $destination, 85);
                break;
            case IMAGETYPE_PNG:
                $success = imagepng($thumb, $destination, 9);
                break;
            case IMAGETYPE_GIF:
                $success = imagegif($thumb, $destination);
                break;
            case IMAGETYPE_WEBP:
                if (function_exists('imagewebp')) {
                    $success = imagewebp($thumb, $destination, 85);
                }
                break;
        }
        
        imagedestroy($image);
        imagedestroy($thumb);
        
        if (!$success) {
             error_log("Failed to save thumbnail: $destination");
        }
        return $success;

    } catch (Exception $e) {
        error_log('Thumbnail creation failed: ' . $e->getMessage() . " for source: $source");
        return false;
    }
}

// Function to handle file deletion
function handleDelete() {
    global $FILES_DIR, $THUMBS_DIR, $ALLOW_FILE_DELETION;

    if (!$ALLOW_FILE_DELETION) {
        echo json_encode(['success' => false, 'error' => 'File deletion is disabled.']);
        return;
    }
    
    $itemPathInput = $_POST['filename'] ?? ''; // 'filename' POST var now refers to item path (file or dir)
    
    // Sanitize the itemPathInput (which is relative to $FILES_DIR)
    $baseFilesDirReal = realpath($FILES_DIR);
    $sanitizedItemRelativePath = '';
    if ($itemPathInput !== '') {
        $normalizedItemPath = trim(str_replace('\\', '/', $itemPathInput), '/');
        if (strpos($normalizedItemPath, '..') === false) {
            $prospectiveItemPath = $baseFilesDirReal . DIRECTORY_SEPARATOR . $normalizedItemPath;
            // realpath checks if the path actually exists. For deletion, it must exist.
            if (realpath($prospectiveItemPath) !== false && strpos(realpath($prospectiveItemPath), $baseFilesDirReal) === 0) {
                $sanitizedItemRelativePath = $normalizedItemPath;
            }
        }
    }

    if (empty($sanitizedItemRelativePath)) {
        echo json_encode(['success' => false, 'error' => 'Invalid item path for deletion.']);
        return;
    }

    $fullItemPathOnServer = $baseFilesDirReal . DIRECTORY_SEPARATOR . $sanitizedItemRelativePath;

    // SECURITY: Double check it's not the root $FILES_DIR itself
    if ($fullItemPathOnServer === $baseFilesDirReal) {
        echo json_encode(['success' => false, 'error' => 'Cannot delete root directory.']);
        return;
    }

    if (!file_exists($fullItemPathOnServer)) {
        echo json_encode(['success' => false, 'error' => 'Item not found.']);
        return;
    }

    if (is_dir($fullItemPathOnServer)) {
        // It's a directory, delete recursively
        if (deleteDirectoryRecursive($fullItemPathOnServer)) {
            // Also attempt to delete corresponding thumbs directory
            $thumbDirToDelete = $THUMBS_DIR . DIRECTORY_SEPARATOR . $sanitizedItemRelativePath;
            if (is_dir($thumbDirToDelete)) {
                deleteDirectoryRecursive($thumbDirToDelete); // Ignores failure for thumbs, main deletion succeeded
            }
            echo json_encode(['success' => true]);
        } else {
            error_log("Failed to delete directory recursively: " . $fullItemPathOnServer);
            echo json_encode(['success' => false, 'error' => 'Failed to delete directory.']);
        }
    } else {
        // It's a file, delete as before
        if (@unlink($fullItemPathOnServer)) {
            // Delete corresponding thumbnail if it exists
            $thumbPath = $THUMBS_DIR . DIRECTORY_SEPARATOR . $sanitizedItemRelativePath;
            $fileExt = strtolower(pathinfo($sanitizedItemRelativePath, PATHINFO_EXTENSION));
            global $VIDEO_PREVIEW_EXTENSIONS, $PDF_THUMB_ENABLED; // Ensure these are accessible
            if (in_array($fileExt, $VIDEO_PREVIEW_EXTENSIONS) || ($fileExt === 'pdf' && $PDF_THUMB_ENABLED && class_exists('Imagick'))) {
                $thumbPath .= '.jpg';
            }
            if (file_exists($thumbPath) && is_file($thumbPath)) {
                @unlink($thumbPath);
            }
            echo json_encode(['success' => true]);
        } else {
            error_log("Failed to delete file: " . $fullItemPathOnServer);
            echo json_encode(['success' => false, 'error' => 'Failed to delete file.']);
        }
    }
}

// Function to handle file listing
function handleList() {
    global $FILES_DIR, $THUMBS_DIR, $TEXT_PREVIEW_EXTENSIONS, $VIDEO_PREVIEW_EXTENSIONS, $AUDIO_PREVIEW_EXTENSIONS, $PDF_THUMB_ENABLED;
    
    $sortBy = $_POST['sortBy'] ?? 'date';
    $sortOrder = $_POST['sortOrder'] ?? 'desc';
    $currentPathInput = $_POST['currentPath'] ?? '';

    // --- Revised Path Sanitization ---
    $baseFilesDirReal = realpath($FILES_DIR);
    if ($baseFilesDirReal === false) {
        error_log("Critical: FILES_DIR '$FILES_DIR' is not a valid path.");
        echo json_encode(['success' => false, 'error' => 'Server configuration error.', 'files' => [], 'currentPath' => '']);
        return;
    }

    $normalizedPathInput = trim(str_replace('\\', '/', $currentPathInput), '/');
    $clientSidePath = ''; // Path to send back to client, relative to $FILES_DIR
    $currentDirForScandir = $baseFilesDirReal; // Actual path to scan on server

    if ($normalizedPathInput !== '' && strpos($normalizedPathInput, '..') === false) {
        $prospectivePath = $baseFilesDirReal . DIRECTORY_SEPARATOR . $normalizedPathInput;
        $currentScannablePathReal = realpath($prospectivePath);

        if ($currentScannablePathReal !== false && strpos($currentScannablePathReal, $baseFilesDirReal) === 0) {
            $currentDirForScandir = $currentScannablePathReal;
            $clientSidePath = $normalizedPathInput;
        }
        // If path is invalid or outside base, $currentDirForScandir remains $baseFilesDirReal and $clientSidePath remains '' (root)
    } else if (strpos($normalizedPathInput, '..') !== false) {
        // Path contained '..', force to root. $currentDirForScandir and $clientSidePath already set to root defaults.
        error_log("Path traversal attempt blocked for input: " . $currentPathInput);
    }
    // --- End Revised Path Sanitization ---

    $files = [];
    if (is_dir($currentDirForScandir)) {
        $items = scandir($currentDirForScandir);
        foreach ($items as $item) {
            if ($item == '.' || $item == '..' || $item == 'thumbs' || $item == '.htaccess' || $item == 'index.html') {
                continue;
            }

            $itemPath = $currentDirForScandir . DIRECTORY_SEPARATOR . $item;
            $isDir = is_dir($itemPath);
            $ext = $isDir ? '' : strtolower(pathinfo($item, PATHINFO_EXTENSION));
            
            $itemSize = 0;
            if ($isDir) {
                $itemSize = getDirectorySize($itemPath);
            } else {
                $itemSize = filesize($itemPath);
            }

            $fileInfo = [
                'name' => $item,
                'isDirectory' => $isDir,
                'size' => $itemSize,
                'modified' => filemtime($itemPath),
                'type' => $isDir ? 'directory' : mime_content_type($itemPath),
                'extension' => $ext,
                'canPreview' => false,
                'previewType' => null
            ];

            if ($isDir) {
                $fileInfo['previewType'] = 'folder';
                $fileInfo['hasThumb'] = false; 
            } else {
                $thumbSubPath = $clientSidePath ? $clientSidePath . DIRECTORY_SEPARATOR . $item : $item;
                $thumbPathForCheck = $THUMBS_DIR . DIRECTORY_SEPARATOR . $thumbSubPath;

                if (in_array($ext, $VIDEO_PREVIEW_EXTENSIONS)) {
                    $thumbPathForCheck .= '.jpg';
                } elseif ($ext === 'pdf' && $PDF_THUMB_ENABLED && class_exists('Imagick')) {
                    $thumbPathForCheck .= '.jpg';
                }
                $fileInfo['hasThumb'] = file_exists($thumbPathForCheck);
                
                if ($ext === 'pdf') { 
                    $fileInfo['canPreview'] = true;
                    $fileInfo['previewType'] = 'pdf';
                } elseif ($fileInfo['hasThumb']) {
                    $fileInfo['canPreview'] = true;
                    if (in_array($ext, $VIDEO_PREVIEW_EXTENSIONS)) {
                        $fileInfo['previewType'] = 'video';
                    } else {
                        $fileInfo['previewType'] = 'image';
                    }
                } elseif (in_array($ext, $TEXT_PREVIEW_EXTENSIONS)) {
                    $fileInfo['canPreview'] = true;
                    $fileInfo['previewType'] = 'text';
                } elseif (in_array($ext, $VIDEO_PREVIEW_EXTENSIONS)) { 
                    $fileInfo['canPreview'] = true;
                    $fileInfo['previewType'] = 'video';
                } elseif (in_array($ext, $AUDIO_PREVIEW_EXTENSIONS)) {
                    $fileInfo['canPreview'] = true;
                    $fileInfo['previewType'] = 'audio';
                } elseif ($ext === 'zip') {
                    $fileInfo['canPreview'] = true;
                    $fileInfo['previewType'] = 'zip';
                }
            }
            
            $files[] = $fileInfo;
        }

        usort($files, function($a, $b) use ($sortBy, $sortOrder) {
            if ($a['isDirectory'] && !$b['isDirectory']) {
                return -1;
            } elseif (!$a['isDirectory'] && $b['isDirectory']) {
                return 1;
            }

            $modifier = ($sortOrder === 'asc') ? 1 : -1;
            switch ($sortBy) {
                case 'name':
                    return strnatcasecmp($a['name'], $b['name']) * $modifier;
                case 'size':
                    return ($a['size'] - $b['size']) * $modifier;
                case 'date':
                default:
                    return ($a['modified'] - $b['modified']) * $modifier;
            }
        });
    }
    
    echo json_encode(['success' => true, 'files' => $files, 'currentPath' => $clientSidePath]);
}

// Function to recursively calculate directory size
function getDirectorySize($dir) {
    $size = 0;
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)) as $file) {
        if ($file->isFile()) {
            $size += $file->getSize();
        }
    }
    return $size;
}

// Function to handle text file preview
function handleTextPreview() {
    global $FILES_DIR, $TEXT_PREVIEW_EXTENSIONS;
    
    $filePathInput = $_POST['filename'] ?? ''; // Input is a relative path

    // Sanitize the filePathInput
    $baseFilesDirReal = realpath($FILES_DIR);
    $sanitizedRelativePath = '';
    if ($filePathInput !== '' && $baseFilesDirReal !== false) {
        $normalizedPath = trim(str_replace('\\', '/', $filePathInput), '/');
        if (strpos($normalizedPath, '..') === false) {
            $prospectiveFullPath = $baseFilesDirReal . DIRECTORY_SEPARATOR . $normalizedPath;
            $realProspectivePath = realpath($prospectiveFullPath);
            if ($realProspectivePath !== false && strpos($realProspectivePath, $baseFilesDirReal) === 0 && is_file($realProspectivePath)) {
                $sanitizedRelativePath = $normalizedPath;
            }
        }
    }

    if (empty($sanitizedRelativePath)) {
        error_log("handleTextPreview: Invalid or non-existent file path. Input: " . $filePathInput);
        echo json_encode(['success' => false, 'error' => 'Invalid file path for text preview']);
        return;
    }

    $fullFilePathOnServer = $baseFilesDirReal . DIRECTORY_SEPARATOR . $sanitizedRelativePath;
    
    $ext = strtolower(pathinfo($sanitizedRelativePath, PATHINFO_EXTENSION));
    if (!in_array($ext, $TEXT_PREVIEW_EXTENSIONS)) {
        echo json_encode(['success' => false, 'error' => 'File type not supported for text preview']);
        return;
    }
    
    // Read file content (limit to 1MB for preview)
    $content = file_get_contents($fullFilePathOnServer, false, null, 0, 1024 * 1024);
    if ($content === false) {
        echo json_encode(['success' => false, 'error' => 'Failed to read file for text preview']);
        return;
    }
    
    // SECURITY: Ensure content is UTF-8
    if (!mb_check_encoding($content, 'UTF-8')) {
        $detectedEncoding = mb_detect_encoding($content, mb_detect_order(), true);
        if ($detectedEncoding) {
            $content = mb_convert_encoding($content, 'UTF-8', $detectedEncoding);
                    } else {
            // If encoding can't be detected, try to force UTF-8, but this might corrupt some characters
            $content = mb_convert_encoding($content, 'UTF-8', 'auto'); 
        }
    }
    
    echo json_encode([
        'success' => true,
        'content' => $content,
        'extension' => $ext,
        'truncated' => filesize($fullFilePathOnServer) > 1024 * 1024
    ]);
}

// Function to handle ZIP contents preview
function handleZipContents() {
    global $FILES_DIR;
    
    $filePathInput = $_POST['filename'] ?? ''; // Input is a relative path

    // Sanitize the filePathInput
    $baseFilesDirReal = realpath($FILES_DIR);
    $sanitizedRelativePath = '';
    if ($filePathInput !== '' && $baseFilesDirReal !== false) {
        $normalizedPath = trim(str_replace('\\', '/', $filePathInput), '/');
        if (strpos($normalizedPath, '..') === false) {
            $prospectiveFullPath = $baseFilesDirReal . DIRECTORY_SEPARATOR . $normalizedPath;
            $realProspectivePath = realpath($prospectiveFullPath);
            if ($realProspectivePath !== false && strpos($realProspectivePath, $baseFilesDirReal) === 0 && is_file($realProspectivePath)) {
                $sanitizedRelativePath = $normalizedPath;
            }
        }
    }

    if (empty($sanitizedRelativePath)) {
        error_log("handleZipContents: Invalid or non-existent file path. Input: " . $filePathInput);
        echo json_encode(['success' => false, 'error' => 'Invalid file path for ZIP preview']);
        return;
    }

    $fullFilePathOnServer = $baseFilesDirReal . DIRECTORY_SEPARATOR . $sanitizedRelativePath;
    
    if (!class_exists('ZipArchive')) {
        echo json_encode(['success' => false, 'error' => 'ZipArchive class not found. Please install the PHP Zip extension.']);
        return;
    }

    $zip = new ZipArchive();
    if ($zip->open($fullFilePathOnServer) === TRUE) {
        $contents = [];
        $totalUncompressed = 0;
        $maxZipEntries = 1000; // Limit number of entries to show
        
        for ($i = 0; $i < min($zip->numFiles, $maxZipEntries); $i++) { 
            $stat = $zip->statIndex($i);
            if ($stat) { // Ensure statIndex returned valid data
                $contents[] = [
                    'name' => $stat['name'],
                    'size' => $stat['size'], // Uncompressed size
                    'compressed' => $stat['comp_size'], // Compressed size
                    'modified' => $stat['mtime']
                ];
                $totalUncompressed += $stat['size'];
            }
        }
        
        $zip->close();
        
        echo json_encode([
            'success' => true,
            'contents' => $contents,
            'totalFiles' => $zip->numFiles, // Report actual total files in zip
            'totalUncompressed' => $totalUncompressed, // Sum of uncompressed sizes of listed files
            'truncated' => $zip->numFiles > $maxZipEntries
        ]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Failed to open ZIP file']);
    }
}

// Function to download all files as ZIP
function downloadAll() {
    global $FILES_DIR, $MAX_ZIP_SIZE, $MAX_ZIP_EXTRACTION_SIZE;
    
    // SECURITY: Rate limit downloads
    rateLimit('download');

    if (!class_exists('ZipArchive')) {
        error_log("ZipArchive class not found for downloadAll. Please install the PHP Zip extension.");
        http_response_code(500);
        die('Server error: ZIP functionality not available.');
    }
    
    $zip = new ZipArchive();
    $zipName = 'files_' . date('Y-m-d_H-i-s') . '.zip';
    $tempZipDir = sys_get_temp_dir();

    // Create a unique temporary file name
    $zipPath = tempnam($tempZipDir, 'sfd_zip_');
    if ($zipPath === false) {
        error_log("Failed to create temporary file for zip in $tempZipDir");
        http_response_code(500);
        die('Server error: Could not create temporary zip file.');
    }
    // tempnam creates a file, but ZipArchive::CREATE needs to create it or overwrite it.
    // So, we unlink it first. ZipArchive will create it again.
    unlink($zipPath);
    // Append .zip to ensure it's treated as such by ZipArchive if it matters
    $zipPath .= '.zip';


    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
        $totalSizeAddedToZip = 0; // This will be compressed size, harder to track against MAX_ZIP_SIZE directly before compression.
                                  // MAX_ZIP_SIZE should ideally be for the final zip file size.
        $totalOriginalFileSize = 0; // Sum of original file sizes added.

        $items = scandir($FILES_DIR);
        if ($items === false) {
            $zip->close();
            unlink($zipPath); // Clean up
            error_log("Failed to scan directory $FILES_DIR for downloadAll.");
            http_response_code(500);
            die('Server error: Could not read files directory.');
        }
        
        foreach ($items as $item) {
            if ($item != '.' && $item != '..' && $item != 'thumbs' && $item != '.htaccess' && $item != 'index.html' && is_file($FILES_DIR . '/' . $item)) {
                $filePath = $FILES_DIR . '/' . $item;
                $fileSize = filesize($filePath);
                
                // SECURITY: Check total original file size against a rough estimate for extraction size
                // This is an estimation, actual compressed size can vary greatly.
                if ($totalOriginalFileSize + $fileSize > $MAX_ZIP_EXTRACTION_SIZE) {
                    $zip->close();
                    unlink($zipPath);
                    error_log("DownloadAll: Estimated extraction size limit exceeded. File: $item, Size: $fileSize, Total: $totalOriginalFileSize");
                    http_response_code(413); // Payload Too Large
                    die('Error: Archive content would exceed maximum allowed extraction size.');
                }
                
                // Add file to zip
                if ($zip->addFile($filePath, $item)) {
                    $totalOriginalFileSize += $fileSize;
                } else {
                    error_log("DownloadAll: Failed to add file to zip: $filePath");
                    // Optionally continue or abort
                }

                // Periodically check current zip size if possible, though ZipArchive doesn't offer easy way to get current size during creation.
                // The MAX_ZIP_SIZE check will be more effective after $zip->close().
            }
        }
        
        $zip->close();
        
        // Now check the final zip size
        if (filesize($zipPath) > $MAX_ZIP_SIZE) {
            unlink($zipPath);
            error_log("DownloadAll: Final zip file size exceeded MAX_ZIP_SIZE. Size: " . filesize($zipPath));
            http_response_code(413);
            die('Error: Archive size limit exceeded.');
        }
        
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . sanitizeFilename($zipName) . '"'); // Sanitize generated zip name too
        header('Content-Length: ' . filesize($zipPath));
        header('Cache-Control: no-cache, must-revalidate');
        header('Pragma: public');
        
        if (ob_get_level()) { // Clean any output buffers
            ob_end_clean();
        }

        readfile($zipPath);
        unlink($zipPath); // Delete temp file after sending
        exit;
    } else {
        error_log("DownloadAll: Failed to open temporary zip file for writing: $zipPath. ZipArchive status: " . $zip->status);
        if (file_exists($zipPath)) unlink($zipPath); // Clean up if open failed but file was created
        http_response_code(500);
        die('Error: Could not create archive. Check server logs.');
    }
}


// Function to download single file
function downloadSingle($filePathInput) { // Parameter is now the relative path from FILES_DIR root
    global $FILES_DIR;
    
    // Sanitize the filePathInput to prevent path traversal but allow subdirectories
    $baseFilesDirReal = realpath($FILES_DIR);
    $sanitizedRelativePath = '';

    if ($filePathInput !== '') {
        // Normalize slashes and remove leading/trailing slashes for the input
        $normalizedPath = trim(str_replace('\\', '/', $filePathInput), '/');
        // Disallow '..' components
        if (strpos($normalizedPath, '..') === false) {
            // Construct the prospective full path
            $prospectiveFullPath = $baseFilesDirReal . DIRECTORY_SEPARATOR . $normalizedPath;
            $realProspectivePath = realpath($prospectiveFullPath); // Check if it resolves to an actual file/dir

            // Ensure the resolved path is within $FILES_DIR and is a file
            if ($realProspectivePath !== false && strpos($realProspectivePath, $baseFilesDirReal) === 0 && is_file($realProspectivePath)) {
                $sanitizedRelativePath = $normalizedPath;
            }
        }
    }

    if (empty($sanitizedRelativePath)) {
        error_log("DownloadSingle: Invalid or non-existent file path after sanitization. Original input: '" . $filePathInput . "'");
        header('HTTP/1.0 400 Bad Request');
        echo 'Invalid filename or path.';
        return;
    }
    
    $fullFilePathOnServer = $baseFilesDirReal . DIRECTORY_SEPARATOR . $sanitizedRelativePath;
    // Redundant check as realpath above would have failed, but good for clarity
    // if (!file_exists($fullFilePathOnServer) || !is_file($fullFilePathOnServer)) { ... }
    
    // SECURITY: Rate limit downloads
    rateLimit('download');
    
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($sanitizedRelativePath) . '"'); // Use basename of the relative path for download filename
    header('Content-Length: ' . filesize($fullFilePathOnServer));
    header('Cache-Control: no-cache, must-revalidate, post-check=0, pre-check=0');
    header('Pragma: public');
    header('Expires: 0');

    if (ob_get_level()) { 
       ob_end_clean();
    }
    
    readfile($fullFilePathOnServer);
    exit; 
}

// New function to handle storage usage request
function handleGetStorageUsage() {
    global $FILES_DIR, $MAX_TOTAL_UPLOAD_SIZE;

    $currentSize = 0;
    if (is_dir($FILES_DIR)) {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($FILES_DIR, RecursiveDirectoryIterator::SKIP_DOTS)
        );
        foreach ($files as $file) {
            if ($file->isFile() && $file->getFilename() !== '.htaccess' && $file->getFilename() !== 'index.html') {
                $currentSize += $file->getSize();
            }
        }
    }

    $percentageUsed = 0;
    if ($MAX_TOTAL_UPLOAD_SIZE > 0) {
        $percentageUsed = round(($currentSize / $MAX_TOTAL_UPLOAD_SIZE) * 100, 2);
    }

    echo json_encode([
        'success' => true,
        'currentSize' => $currentSize,
        'maxSize' => $MAX_TOTAL_UPLOAD_SIZE,
        'percentageUsed' => $percentageUsed
    ]);
}

// Function to handle downloading selected files as ZIP
function handleDownloadSelectedZip() {
    global $FILES_DIR, $MAX_ZIP_SIZE, $MAX_ZIP_EXTRACTION_SIZE;

    // No direct CSRF validation here as it\'s a POST from a JS-built form,
    // but the main AJAX handler would have already validated CSRF if this were a typical AJAX call.
    // For direct form POSTs like this for download, ensure it only proceeds if authenticated.
    if ($GLOBALS['PASSWORD_PROTECTION'] && !isset($_SESSION['authenticated'])) {
        http_response_code(403);
        die('Authentication required.');
    }
    // However, it\'s better to include CSRF check for consistency if possible or ensure actions are idempotent/safe.
    // Let's assume CSRF is handled by the initial page load context for form submission.
    // If strict CSRF for this specific action is needed, JS must send it, and PHP check it.
    // For simplicity, relying on session auth for this download action.

    if (!isset($_POST['filenames']) || !is_array($_POST['filenames'])) {
        http_response_code(400);
        die('No filenames provided or invalid format.');
    }

    $filenames = $_POST['filenames'];
    if (empty($filenames)) {
        http_response_code(400);
        die('No files selected for download.');
    }

    // SECURITY: Rate limit downloads (use a generic action name for selected downloads)
    rateLimit('download_selected');

    if (!class_exists('ZipArchive')) {
        error_log("ZipArchive class not found for downloadSelected. Please install the PHP Zip extension.");
        http_response_code(500);
        die('Server error: ZIP functionality not available.');
    }

    $zip = new ZipArchive();
    $zipName = 'selected_files_' . date('Y-m-d_H-i-s') . '.zip';
    $tempZipDir = sys_get_temp_dir();
    $zipPath = tempnam($tempZipDir, 'sfd_sel_zip_');
    if ($zipPath === false) {
        error_log("Failed to create temporary file for selected zip in $tempZipDir");
        http_response_code(500);
        die('Server error: Could not create temporary zip file.');
    }
    unlink($zipPath); // tempnam creates a file, ZipArchive needs to create or overwrite.
    $zipPath .= '.zip';

    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
        $totalOriginalFileSize = 0;
        $addedFileCount = 0;

        foreach ($filenames as $unsafeFilename) {
            $filename = sanitizeFilename($unsafeFilename);
            if (empty($filename)) {
                error_log("DownloadSelected: Empty filename after sanitization. Original: '$unsafeFilename'");
                continue; // Skip invalid filename
            }

            $filePath = $FILES_DIR . '/' . $filename;
            
            // SECURITY: Verify file is within allowed directory and exists
            $realPath = realpath($filePath);
            $realBasePath = realpath($FILES_DIR);
            if ($realPath === false || strpos($realPath, $realBasePath . DIRECTORY_SEPARATOR) !== 0 || $realPath === $realBasePath || !is_file($realPath)) {
                 error_log("Path traversal attempt or invalid file path for selected download: User tried '$unsafeFilename', sanitized to '$filename', resolved to '$realPath'");
                continue; // Skip invalid or non-existent file
            }

            $fileSize = filesize($realPath);
            if ($totalOriginalFileSize + $fileSize > $MAX_ZIP_EXTRACTION_SIZE) {
                // This check is against a combined limit. Could also check final zip size against $MAX_ZIP_SIZE.
                error_log("DownloadSelected: Estimated extraction size limit would be exceeded. File: $filename");
                // Potentially stop or notify user. For now, we'll just skip adding more files if we had a hard limit here.
                // This behavior might be complex; for now, let it try to add and check final zip size.
            }

            if ($zip->addFile($realPath, $filename)) {
                $totalOriginalFileSize += $fileSize;
                $addedFileCount++;
            } else {
                error_log("DownloadSelected: Failed to add file to zip: $filePath");
            }
        }
        
        $zip->close();

        if ($addedFileCount === 0) {
            unlink($zipPath);
            http_response_code(404); // Or another appropriate code
            die('No valid files were found to include in the archive. Ensure files exist and names are correct.');
        }

        if (filesize($zipPath) > $MAX_ZIP_SIZE) {
            unlink($zipPath);
            error_log("DownloadSelected: Final zip file size exceeded MAX_ZIP_SIZE. Size: " . filesize($zipPath));
            http_response_code(413);
            die('Error: Archive size limit exceeded.');
        }

        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . sanitizeFilename($zipName) . '"');
        header('Content-Length: ' . filesize($zipPath));
        header('Cache-Control: no-cache, must-revalidate');
        header('Pragma: public');
        if (ob_get_level()) ob_end_clean();
        readfile($zipPath);
        unlink($zipPath);
        exit;
    } else {
        error_log("DownloadSelected: Failed to open temporary zip file for writing: $zipPath. ZipArchive status: " . $zip->status);
        if (file_exists($zipPath)) unlink($zipPath);
        http_response_code(500);
        die('Error: Could not create archive. Check server logs.');
    }
}

// Handle folder download as ZIP
if (isset($_GET['download_folder'])) {
    if (!$PASSWORD_PROTECTION || isset($_SESSION['authenticated'])) {
        $folderPathRelative = $_GET['download_folder'];
        
        // Basic sanitization: prevent .. and ensure it's not empty after sanitization.
        // Normalize slashes first, then trim, then check for ..
        $normalizedPath = str_replace('\\', '/', $folderPathRelative);
        $normalizedPath = trim($normalizedPath, '/');
        
        if (empty($normalizedPath) || strpos($normalizedPath, '..') !== false) {
            http_response_code(400);
            error_log("Attempt to download folder with invalid path: " . $folderPathRelative);
            die('Invalid folder path specified.');
        }
        $zipName = basename($normalizedPath) . '.zip';
        downloadDirectoryAsZip($normalizedPath, $zipName);
    } else {
        http_response_code(403);
        die('Authentication required.');
    }
    exit;
}

// Recursive function to add files and subdirectories to a ZIP file
function addFolderToZip($folderPath, $zipArchive, $basePathInZip, &$totalOriginalFileSize) {
    global $FILES_DIR, $MAX_ZIP_EXTRACTION_SIZE; // Access global for limits

    $items = @scandir($folderPath);
    if ($items === false) {
        error_log("addFolderToZip: Failed to scan directory: " . $folderPath);
        return; // Or handle error, maybe throw exception
    }

    foreach ($items as $item) {
        if ($item == '.' || $item == '..') {
            continue;
        }
        $itemFullPath = $folderPath . DIRECTORY_SEPARATOR . $item;
        $itemPathInZip = $basePathInZip . $item;

        if (is_dir($itemFullPath)) {
            $zipArchive->addEmptyDir($itemPathInZip);
            addFolderToZip($itemFullPath, $zipArchive, $itemPathInZip . '/', $totalOriginalFileSize);
        } elseif (is_file($itemFullPath)) {
            $fileSize = filesize($itemFullPath);
            if ($MAX_ZIP_EXTRACTION_SIZE > 0 && ($totalOriginalFileSize + $fileSize > $MAX_ZIP_EXTRACTION_SIZE)) {
                error_log("addFolderToZip: Estimated extraction size limit exceeded. File: $itemPathInZip, Size: $fileSize, Total: $totalOriginalFileSize");
                throw new Exception('Archive content would exceed maximum allowed extraction size.');
            }
            if ($zipArchive->addFile($itemFullPath, $itemPathInZip)) {
                $totalOriginalFileSize += $fileSize;
            } else {
                error_log("addFolderToZip: Failed to add file to zip: $itemFullPath as $itemPathInZip");
                // Optionally throw an exception or handle error
            }
        }
    }
}

// Function to download a specific directory as ZIP
function downloadDirectoryAsZip($folderPathRelative, $zipName) {
    global $FILES_DIR, $MAX_ZIP_SIZE, $MAX_ZIP_EXTRACTION_SIZE; 

    rateLimit('download_folder'); 

    $baseFilesDirReal = realpath($FILES_DIR);
    if ($baseFilesDirReal === false) { // Should not happen if FILES_DIR is valid
        error_log("downloadDirectoryAsZip: Invalid FILES_DIR configuration.");
        http_response_code(500);
        die('Server configuration error.');
    }
    
    $fullFolderPath = $baseFilesDirReal . DIRECTORY_SEPARATOR . $folderPathRelative;
    $fullFolderPathReal = realpath($fullFolderPath);

    if ($fullFolderPathReal === false || strpos($fullFolderPathReal, $baseFilesDirReal) !== 0 || !is_dir($fullFolderPathReal) || $fullFolderPathReal === $baseFilesDirReal) {
        error_log("downloadDirectoryAsZip: Invalid or non-directory path specified: " . $folderPathRelative . " (Resolved: " . $fullFolderPathReal . ")");
        http_response_code(404);
        die('Folder not found or access denied.');
    }

    if (!class_exists('ZipArchive')) {
        error_log("ZipArchive class not found for downloadDirectoryAsZip. Please install the PHP Zip extension.");
        http_response_code(500);
        die('Server error: ZIP functionality not available.');
    }

    $zip = new ZipArchive();
    $tempZipDir = sys_get_temp_dir();
    $zipPath = tempnam($tempZipDir, 'sfd_folder_zip_');
    if ($zipPath === false) {
        error_log("Failed to create temporary file for folder zip in $tempZipDir");
        http_response_code(500);
        die('Server error: Could not create temporary zip file.');
    }
    unlink($zipPath); 
    $zipPath .= '.zip';

    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
        $totalOriginalFileSize = 0; 
        try {
            addFolderToZip($fullFolderPathReal, $zip, '', $totalOriginalFileSize);
        } catch (Exception $e) {
            $zip->close();
            unlink($zipPath);
            error_log("downloadDirectoryAsZip: Exception during zipping - " . $e->getMessage());
            http_response_code(413); 
            die('Error: ' . $e->getMessage());
        }

        $zip->close();

        if ($MAX_ZIP_SIZE > 0 && filesize($zipPath) > $MAX_ZIP_SIZE) {
            unlink($zipPath);
            error_log("downloadDirectoryAsZip: Final zip file size exceeded MAX_ZIP_SIZE. Size: " . filesize($zipPath));
            http_response_code(413);
            die('Error: Archive size limit exceeded.');
        }

        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . sanitizeFilename($zipName) . '"');
        header('Content-Length: ' . filesize($zipPath));
        header('Cache-Control: no-cache, must-revalidate');
        header('Pragma: public');
        if (ob_get_level()) ob_end_clean();
        readfile($zipPath);
        unlink($zipPath);
        exit;
    } else {
        error_log("downloadDirectoryAsZip: Failed to open temporary zip file for writing: $zipPath. ZipArchive status: " . $zip->status);
        if (file_exists($zipPath)) unlink($zipPath);
        http_response_code(500);
        die('Error: Could not create archive. Check server logs.');
    }
}

// Function to handle creating a new folder
function handleCreateFolder() {
    global $FILES_DIR;

    $folderNameInput = $_POST['folderName'] ?? '';
    $currentPathInput = $_POST['currentPath'] ?? '';

    // 1. Sanitize folderNameInput: allow only valid filename characters, no slashes or traversal.
    // Use a simplified version of sanitizeFilename, focusing on the name part.
    $sanitizedFolderName = preg_replace('/[^a-zA-Z0-9_\- ]/', '_', $folderNameInput); // Allow spaces, replace others with underscore
    $sanitizedFolderName = preg_replace('/_+/', '_', $sanitizedFolderName); // Consolidate underscores
    $sanitizedFolderName = trim($sanitizedFolderName, '_');
    if (empty($sanitizedFolderName) || $sanitizedFolderName === '.' || $sanitizedFolderName === '..') {
        echo json_encode(['success' => false, 'error' => 'Invalid folder name provided.']);
        return;
    }
    if (strlen($sanitizedFolderName) > 200) { // Arbitrary length limit for folder names
        $sanitizedFolderName = substr($sanitizedFolderName, 0, 200);
    }

    // 2. Sanitize currentPathInput (path active in UI)
    $baseFilesDirReal = realpath($FILES_DIR);
    if ($baseFilesDirReal === false) {
        echo json_encode(['success' => false, 'error' => 'Server configuration error: Invalid base files directory.']); return;
    }
    $sanitizedUiPathRelative = ''; // Relative to $FILES_DIR
    if ($currentPathInput !== '') {
        $normalizedUiPath = trim(str_replace('\\', '/', $currentPathInput), '/');
        if (strpos($normalizedUiPath, '..') === false) {
            $prospectiveUiPath = $baseFilesDirReal . DIRECTORY_SEPARATOR . $normalizedUiPath;
            if (realpath($prospectiveUiPath) !== false && strpos(realpath($prospectiveUiPath), $baseFilesDirReal) === 0 && is_dir(realpath($prospectiveUiPath))) {
                $sanitizedUiPathRelative = $normalizedUiPath;
            }
        } // If path is bad, it defaults to root ($sanitizedUiPathRelative remains '')
    }

    // 3. Construct the full path for the new folder
    $newFolderPath = $baseFilesDirReal . 
                       ($sanitizedUiPathRelative ? DIRECTORY_SEPARATOR . $sanitizedUiPathRelative : '') .
                       DIRECTORY_SEPARATOR . $sanitizedFolderName;

    // 4. Check if a file or folder with that name already exists
    if (file_exists($newFolderPath)) {
        echo json_encode(['success' => false, 'error' => 'A file or folder with this name already exists.']);
        return;
    }

    // 5. Create the new directory
    if (@mkdir($newFolderPath, 0755)) { // No need for recursive, creating one level
        // 6. Secure the new folder
        createHtaccessInDirectory($newFolderPath);
        createIndexHtmlInDirectory($newFolderPath);
        echo json_encode(['success' => true]);
    } else {
        error_log("Failed to create directory: " . $newFolderPath);
        echo json_encode(['success' => false, 'error' => 'Could not create the folder on the server.']);
    }
}

// *** NEW FUNCTION: handleRename ***
function handleRename() {
    global $FILES_DIR, $THUMBS_DIR, $VIDEO_PREVIEW_EXTENSIONS, $PDF_THUMB_ENABLED;

    $itemIdentifier = $_POST['itemIdentifier'] ?? ''; // Full relative path from FILES_DIR root
    $newNameRaw = $_POST['newName'] ?? '';

    // 1. Validate and sanitize itemIdentifier (current path)
    $baseFilesDirReal = realpath($FILES_DIR);
    if ($baseFilesDirReal === false) {
        echo json_encode(['success' => false, 'error' => 'Server configuration error: Invalid base files directory.']); return;
    }

    $currentItemRelativePath = '';
    if ($itemIdentifier !== '') {
        $normalizedItemPath = trim(str_replace('\\\\', '/', $itemIdentifier), '/');
        if (strpos($normalizedItemPath, '..') === false) {
            $prospectiveItemPath = $baseFilesDirReal . DIRECTORY_SEPARATOR . $normalizedItemPath;
            if (realpath($prospectiveItemPath) !== false && strpos(realpath($prospectiveItemPath), $baseFilesDirReal) === 0) {
                $currentItemRelativePath = $normalizedItemPath;
            }
        }
    }

    if (empty($currentItemRelativePath)) {
        echo json_encode(['success' => false, 'error' => 'Invalid current item path.']);
        return;
    }

    $oldFullPath = $baseFilesDirReal . DIRECTORY_SEPARATOR . $currentItemRelativePath;
    if (!file_exists($oldFullPath)) {
        echo json_encode(['success' => false, 'error' => 'Item to rename not found.']);
        return;
    }

    // 2. Sanitize newNameRaw
    if (empty(trim($newNameRaw))) {
        echo json_encode(['success' => false, 'error' => 'New name cannot be empty.']);
        return;
    }

    $isDir = is_dir($oldFullPath);
    $finalNewName = '';
    $originalNamePartForNew = pathinfo($newNameRaw, PATHINFO_FILENAME);
    $originalExtensionForNew = strtolower(pathinfo($newNameRaw, PATHINFO_EXTENSION));

    if ($isDir) {
        // For directories, sanitize the whole newNameRaw as a folder name
        // Use a simplified sanitization, similar to create_folder
        $sanitizedNewFolderName = preg_replace('/[^a-zA-Z0-9 _\\-.()[\\]\\,]/', '_', $newNameRaw);
        $sanitizedNewFolderName = preg_replace('/[_\\s]+/', '_', $sanitizedNewFolderName);
        $sanitizedNewFolderName = trim($sanitizedNewFolderName, '_');
        if (empty($sanitizedNewFolderName) || $sanitizedNewFolderName === '.' || $sanitizedNewFolderName === '..') {
            echo json_encode(['success' => false, 'error' => 'Invalid new folder name after sanitization.']);
            return;
        }
        if (strlen($sanitizedNewFolderName) > 200) {
            $sanitizedNewFolderName = substr($sanitizedNewFolderName, 0, 200);
        }
        $finalNewName = $sanitizedNewFolderName;
    } else {
        // For files, sanitize the name part, keep original extension from $newNameRaw
        $sanitizedNewNamePart = sanitizeFilename($originalNamePartForNew . (empty($originalExtensionForNew) ? '' : '.dummy')); // Use sanitizeFilename for the name part
        $finalNewName = pathinfo($sanitizedNewNamePart, PATHINFO_FILENAME); // Get the sanitized name part

        if (!empty($originalExtensionForNew)) {
            $finalNewName .= '.' . $originalExtensionForNew; // Re-attach original extension from newName
        } else {
            // If new name has no extension, try to use original file's extension
             $originalFileExtension = strtolower(pathinfo($currentItemRelativePath, PATHINFO_EXTENSION));
             if (!empty($originalFileExtension)) {
                 $finalNewName .= '.' . $originalFileExtension;
             }
        }
    }
    
    if (empty($finalNewName)) {
        echo json_encode(['success' => false, 'error' => 'New name became empty after sanitization.']);
        return;
    }

    // 3. Construct new path and check for conflicts
    $parentDirRelativePath = dirname($currentItemRelativePath);
    if ($parentDirRelativePath === '.') $parentDirRelativePath = ''; // Handle root directory

    $newRelativePath = ($parentDirRelativePath ? $parentDirRelativePath . '/' : '') . $finalNewName;
    $newFullPath = $baseFilesDirReal . DIRECTORY_SEPARATOR . $newRelativePath;

    if ($oldFullPath === $newFullPath) {
        echo json_encode(['success' => true, 'message' => 'No change in name.']); // Technically success, no operation needed.
        return;
    }

    if (file_exists($newFullPath)) {
        echo json_encode(['success' => false, 'error' => 'An item with the new name already exists in this location.']);
        return;
    }

    // 4. Perform rename
    if (rename($oldFullPath, $newFullPath)) {
        // 5. Handle thumbnail rename for files
        if (!$isDir) {
            $oldThumbPath = '';
            $newThumbPath = '';

            $oldFileExt = strtolower(pathinfo($currentItemRelativePath, PATHINFO_EXTENSION));
            $newFileExt = strtolower(pathinfo($newRelativePath, PATHINFO_EXTENSION)); // Should be same unless ext changed

            // Construct old thumb path
            $oldThumbNamePart = $currentItemRelativePath;
            if (in_array($oldFileExt, $VIDEO_PREVIEW_EXTENSIONS) || ($oldFileExt === 'pdf' && $PDF_THUMB_ENABLED && class_exists('Imagick'))) {
                $oldThumbNamePart .= '.jpg';
            }
            $oldThumbPath = realpath($THUMBS_DIR) . DIRECTORY_SEPARATOR . $oldThumbNamePart;
            
            // Construct new thumb path
            $newThumbNamePart = $newRelativePath;
             if (in_array($newFileExt, $VIDEO_PREVIEW_EXTENSIONS) || ($newFileExt === 'pdf' && $PDF_THUMB_ENABLED && class_exists('Imagick'))) {
                $newThumbNamePart .= '.jpg';
            }
            // Ensure the target directory for the new thumb exists
            $newThumbDir = dirname(realpath($THUMBS_DIR) . DIRECTORY_SEPARATOR . $newThumbNamePart);
            if (!is_dir($newThumbDir)) {
                ensureSecurePath(realpath($THUMBS_DIR), dirname($newRelativePath . ($in_array($newFileExt, $VIDEO_PREVIEW_EXTENSIONS) || ($newFileExt === 'pdf' && $PDF_THUMB_ENABLED && class_exists('Imagick')) ? '.jpg':'')));
            }
            $newThumbPath = realpath($THUMBS_DIR) . DIRECTORY_SEPARATOR . $newThumbNamePart;

            if (file_exists($oldThumbPath) && is_file($oldThumbPath) && !empty($newThumbPath)) {
                // The directory for the new thumb ($newThumbDir) should have been ensured above.
                if (!rename($oldThumbPath, $newThumbPath)) {
                     error_log("Failed to rename thumbnail from {$oldThumbPath} to {$newThumbPath}");
                     // Don't fail the whole operation, but log it.
                }
            }
        }
        echo json_encode(['success' => true]);
    } else {
        error_log("Failed to rename item from {$oldFullPath} to {$newFullPath}");
        echo json_encode(['success' => false, 'error' => 'Failed to rename the item on the server.']);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($SITE_TITLE); ?></title>
    <style>
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f5f5f5;
            --bg-tertiary: #e0e0e0;
            --text-primary: #333333;
            --text-secondary: #666666;
            --border-color: #dddddd;
            --accent-color:#367e39;
            --danger-color: #f44336;
            --shadow: rgba(0, 0, 0, 0.1);
        }
        
        [data-theme="dark"] {
            --bg-primary: #1e1e1e;
            --bg-secondary: #2d2d2d;
            --bg-tertiary: #3d3d3d;
            --text-primary: #ffffff;
            --text-secondary: #b0b0b0;
            --border-color: #444444;
            --accent-color: #367e39;
            --danger-color: #ef5350;
            --shadow: rgba(0, 0, 0, 0.3);
        }
        
        .file-checkbox {
            display: none;
        }
        .container.selection-active .file-checkbox {
            display: inline-block;
        }

        /* Style for selected file items */
        .file-item.selected, .file-card.selected {
            background-color: var(--accent-color) !important; /* Use !important to override hover if needed */
        }
        .file-item.selected .file-details h4,
        .file-item.selected .file-details p,
        .file-card.selected h4,
        .file-card.selected p {
            color: white !important;
        }

        /* Adjust gradient for selected file items in list view */
        .file-item.selected .file-actions {
             /* background: linear-gradient(...) removed */
        }
        .file-item.selected .file-actions::before {
            /* Removed as ::before is hidden */
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-secondary);
            color: var(--text-primary);
            line-height: 1.6;
            transition: background-color 0.3s, color 0.3s;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
        }
        
        .header h1 {
            font-size: 2rem;
            font-weight: 600;
        }
        
        .header-controls {
            display: flex;
            gap: 1rem;
            align-items: center;
        }
        
        .theme-toggle {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 5px; /* Changed from 20px for consistency */
            padding: 0.5rem 1rem;
            cursor: pointer;
            transition: all 0.3s;
            color: var(--text-primary);
        }
        
        .theme-toggle:hover {
            background: var(--bg-tertiary); /* Keep original background */
            border-color: var(--accent-color); /* Change border to accent */
            color: var(--accent-color); /* Change text to accent */
        }

        .theme-toggle:active {
            background: var(--border-color); /* Slightly different background for pressed feel */
            border-color: var(--accent-color);
            color: var(--accent-color);
        }
        
        .upload-area {
            background: var(--bg-primary);
            border: 2px dashed var(--border-color);
            border-radius: 10px;
            padding: 3rem;
            text-align: center;
            margin-bottom: 2rem;
            transition: all 0.3s;
            box-shadow: 0 2px 10px var(--shadow);
        }
        
        .upload-area.dragover {
            border-color: var(--accent-color);
            background: var(--bg-secondary);
        }
        
        .upload-area h3 {
            margin-bottom: 1rem;
            color: var(--text-primary);
        }
        
        .upload-area p {
            color: var(--text-secondary);
            margin-bottom: 1.5rem;
        }
        
        .file-input {
            display: none;
        }
        
        .btn {
            display: inline-block;
            padding: 0.5rem 1rem; /* Changed from 0.75rem 1.5rem to match view-btn */
            background: var(--accent-color);
            color: white;
            text-decoration: none;
            border-radius: 5px;
            /* border: none; */ /* Replaced by specific border below */
            border: 1px solid var(--accent-color);
            cursor: pointer;
            font-size: 0.875rem; /* Changed from 1rem */
            transition: all 0.3s;
        }
        
        .btn:hover {
            /* background: #45a049; */ /* Old hardcoded green */
            /* transform: translateY(-2px); */ /* Removing transform for consistency */
            /* box-shadow: 0 4px 15px var(--shadow); */ /* Removing shadow for consistency */
            background: var(--bg-primary);
            color: var(--accent-color);
            border-color: var(--accent-color);
        }
        
        .btn-danger {
            background: var(--danger-color);
            border-color: var(--danger-color);
        }
        
        .btn-danger:hover {
            /* background: #da190b; */ /* Old hardcoded red */
            background: var(--bg-primary);
            color: var(--danger-color);
            border-color: var(--danger-color);
        }
        
        .btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }
        
        .btn-secondary:hover {
            /* background: var(--accent-color); */ /* Old: turned green */
            /* color: white; */
            /* border-color: var(--accent-color); */
            background: var(--bg-tertiary); /* Keep original background */
            color: var(--accent-color);      /* Change text to accent */
            border-color: var(--accent-color);/* Change border to accent */
        }
        
        .file-actions {
            display: flex;
            gap: 0.5rem;
            position: absolute;
            right: 0;
            top: 50%;
            transform: translateY(-50%);
            z-index: 10;
            padding: 0.25rem 1rem; /* Keep some padding around buttons */
            /* background: linear-gradient(...) removed */
        }
        
        .file-actions::before {
            display: none; /* Remove the pseudo-element used for gradient */
        }
        
        /* Add box shadow to buttons within file-actions */
        .file-actions .btn {
            box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24);
            /* transition: box-shadow 0.3s cubic-bezier(.25,.8,.25,1); Optional transition */
        }

        .file-item:hover .file-actions .btn {
            box-shadow: 0 3px 6px rgba(0,0,0,0.1), 0 2px 4px rgba(0,0,0,0.07); /* Lighter shadow for hover, or themed */
            /* Or to match hover background: box-shadow: 0 2px 5px 0 var(--bg-secondary); */ 
        }

        .file-item.selected .file-actions .btn {
            box-shadow: 0 2px 4px 0 var(--accent-color), 0 2px 5px 0 var(--accent-color); /* Shadow matching accent color, slightly adjusted */
        }
        
        .file-item:hover .file-actions::before {
            /* Removed as ::before is hidden */
        }

        /* Ensure the main actions area also changes on hover */
        .file-item:hover .file-actions {
            /* background: linear-gradient(...) removed - background will be inherited or transparent */
        }
        
        .icon-btn {
            width: 36px;
            height: 36px;
            padding: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.4rem;
            border-radius: 5px; /* Changed from 50% for consistency */
            line-height: 1;
            font-weight: bold;
        }
        
        .controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            background: var(--bg-primary);
            padding: 1rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px var(--shadow);
            flex-wrap: wrap;
            gap: 1rem;
        }
        
        .controls-left {
            display: flex;
            gap: 1rem;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .view-toggle {
            display: flex;
            gap: 0.5rem;
        }
        
        .sort-controls {
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }
        
        .sort-select {
            padding: 0.5rem 1rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 5px;
            color: var(--text-primary);
            cursor: pointer;
            font-size: 0.875rem;
        }
        
        .view-btn {
            padding: 0.5rem 1rem; /* Keep padding for size */
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            cursor: pointer;
            transition: all 0.3s;
            border-radius: 5px;
            color: var(--text-primary);
            font-size: 1.2rem; /* Increase font size for icons */
            line-height: 1; /* Adjust line height for icon centering */
            min-width: 44px; /* Ensure decent tap target */
            text-align: center;
        }

        #toggleSelectionModeBtn {
            font-size: 1.2rem; /* Match view-btn icon size */
            line-height: 1;
            min-width: 44px;
            padding: 0.5rem 1rem; /* Consistent padding */
        }
        
        .view-btn.active {
            background: var(--accent-color);
            color: white;
            border-color: var(--accent-color);
        }
        
        .view-btn:hover {
            background: var(--bg-tertiary); /* Keep original background */
            color: var(--accent-color);      /* Change text to accent */
            border-color: var(--accent-color);/* Change border to accent */
        }

        .view-btn.active:hover {
            filter: brightness(90%); /* Darken slightly, keep colors */
            /* Override general .view-btn:hover to prevent color/bg change */
            background: var(--accent-color); 
            color: white;
            border-color: var(--accent-color);
        }
        
        .files-container {
            background: var(--bg-primary);
            border-radius: 10px;
            padding: 1rem;
            box-shadow: 0 2px 10px var(--shadow);
        }
        
        .list-view {
            display: none;
        }
        
        .list-view.active {
            display: block;
        }
        
        .file-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
            transition: background 0.3s;
            position: relative;
            overflow: hidden;
        }
        
        .file-item:hover {
            background: var(--bg-secondary);
        }
        
        .file-item:last-of-type {
            border-bottom: none;
        }
        
        .file-info {
            display: flex;
            align-items: center;
            gap: 1rem;
            flex: 1;
            cursor: pointer;
            text-decoration: none;
            color: inherit;
            transition: opacity 0.2s;
            overflow: hidden;
            padding-right: 110px; /* Space for buttons */
        }
        
        .file-info:hover {
            opacity: 0.8;
        }
        
        .file-details {
            flex: 1;
            overflow: hidden;
        }
        
        .file-details h4 {
            font-weight: 500;
            margin-bottom: 0.25rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .file-details h4:hover {
            text-decoration: none;
        }
        
        .file-details p {
            font-size: 0.875rem;
            color: var(--text-secondary);
            white-space: nowrap;
        }
        
        .tooltip {
            position: absolute;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            padding: 0.5rem 0.75rem;
            border-radius: 5px;
            font-size: 0.875rem;
            pointer-events: none;
            z-index: 1000;
            max-width: 400px;
            word-wrap: break-word;
            box-shadow: 0 2px 10px var(--shadow);
            opacity: 0;
            transition: opacity 0.2s;
        }
        
        .tooltip.show {
            opacity: 1;
        }
        
        .file-icon {
            width: 40px;
            height: 40px;
            background: var(--bg-tertiary);
            border-radius: 5px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            overflow: hidden;
            position: relative;
        }
        
        .file-icon img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        
        .file-icon-large {
            font-size: 4rem;
            color: var(--text-secondary);
        }
        
        .file-icon.has-preview::after {
            content: '👁';
            position: absolute;
            bottom: -2px;
            right: -2px;
            font-size: 0.65rem;
            background: rgba(255, 255, 255, 0.9);
            color: var(--text-primary);
            width: 16px;
            height: 16px;
            border-radius: 5px; /* Match other button radii */
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0;
            transition: opacity 0.2s;
            line-height: 1;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
        }
        
        /* New wrapper for icon view thumbnails to contain the overlay */
        .file-preview .thumbnail-wrapper {
            position: relative;
            display: inline-block; 
            /* Ensure wrapper takes full space of .file-preview for consistent sizing */
            width: 100%; 
            height: 100%; 
            line-height: 0; 
            border-radius: inherit; 
            overflow: hidden; /* Important for object-fit:cover to work as expected with border-radius */
        }

        .file-preview .thumbnail-wrapper img,
        .file-preview .thumbnail-wrapper .file-icon-large {
            width: 100%;
            height: 100%; 
            display: block; 
            object-fit: cover; /* This will fill the area, cropping if necessary */
            border-radius: inherit;
        }
        .file-preview .thumbnail-wrapper .file-icon-large {
            width: 100%; 
            height: 100%; 
            display: flex;
            align-items: center;
            justify-content: center;
        }

        /* Updated overlay styles for hover effect and different sizes */
        .video-thumb-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            background-color: rgba(0, 0, 0, 0.3);
            color: white;
            opacity: 0.8; /* Visible by default with some transparency */
            /* transition: opacity 0.2s ease-in-out; */ /* No transition needed if always visible */
            pointer-events: none;
            border-radius: inherit; 
            z-index: 1;
        }

        /* List view: specific styles */
        .file-icon .video-thumb-overlay {
            font-size: 1.8rem; 
        }
        /* .file-icon:hover .video-thumb-overlay { 
            opacity: 0.8;
        } */ /* Removed hover effect, always visible */

        /* Icon view: specific styles */
        .thumbnail-wrapper .video-thumb-overlay { 
            font-size: 2.5rem; /* Larger for icon view */
        }
        /* .thumbnail-wrapper:hover .video-thumb-overlay { 
            opacity: 0.8;
        } */ /* Removed hover effect, always visible */

        .file-info:hover .file-icon.has-preview::after {
            opacity: 1;
        }
        
        .file-details h4 {
            font-weight: 500;
            margin-bottom: 0.25rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .file-details p {
            font-size: 0.875rem;
            color: var(--text-secondary);
        }
        
        .icon-view {
            display: none;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 1rem;
        }
        
        .icon-view.active {
            display: grid;
        }
        
        .file-card {
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 1rem;
            text-align: center;
            transition: all 0.3s;
            position: relative;
        }
        
        .file-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px var(--shadow);
        }
        
        .file-preview {
            width: 100%;
            height: 150px;
            background: var(--bg-tertiary);
            border-radius: 5px;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            transition: transform 0.2s;
        }
        
        .file-preview[onclick] {
            cursor: pointer;
        }
        
        .file-preview[onclick]:hover {
            transform: scale(1.02);
        }
        
        .file-preview img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        
        .file-preview .file-icon-large {
            font-size: 4rem;
            color: var(--text-secondary);
        }
        
        .file-card h4 {
            font-size: 0.875rem;
            font-weight: 500;
            margin-bottom: 0.5rem;
            word-break: break-all;
        }
        
        .file-card p {
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-bottom: 1rem;
        }
        
        .file-card-actions {
            display: flex;
            gap: 0.5rem;
            justify-content: center;
            margin-top: 0.5rem;
        }
        
        .progress-container {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            width: 300px;
            z-index: 1000;
        }
        
        .progress-item {
            background: var(--bg-primary);
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 1rem;
            box-shadow: 0 4px 20px var(--shadow);
        }
        
        .progress-item h4 {
            font-size: 0.875rem;
            margin-bottom: 0.5rem;
            word-break: break-all;
        }
        
        .progress-bar {
            width: 100%;
            height: 10px;
            background: var(--bg-tertiary);
            border-radius: 5px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: var(--accent-color);
            transition: width 0.3s;
        }
        
        /* Preview modals */
        .preview-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.9);
            z-index: 2000;
            align-items: center;
            justify-content: center;
        }
        
        .preview-modal.active {
            display: flex;
        }
        
        .preview-close {
            position: absolute;
            top: 0px;    /* Flush to top for all preview modals */
            right: 0px;   /* Flush to right for all preview modals */
            width: 32px; /* Standardized smaller size */
            height: 32px; /* Standardized smaller size */
            background: rgba(255, 255, 255, 0.1);
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 0px; /* Sharp square corners for all previews */
            font-size: 1.2rem; /* Standardized icon size */
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s;
            z-index: 2010; /* Ensure close button is above content */
        }
        
        /* REMOVE/Ensure Specific adjustments for lightbox close button are removed if they differ from above */
        /* #lightbox .preview-close {
            width: 32px; 
            height: 32px; 
            top: 0px;    
            right: 0px;   
            font-size: 1.2rem; 
            border-radius: 0px; 
        } */

        .preview-close:hover {
            background: rgba(255, 255, 255, 0.2);
        }
        
        .preview-title {
            position: absolute;
            top: 1rem;
            left: 1rem;
            color: white;
            font-size: 1.2rem;
            background: rgba(0, 0, 0, 0.5);
            padding: 0.5rem 1rem;
            border-radius: 5px;
            z-index: 2010;
        }
        
        /* Image lightbox */
        .lightbox {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.9);
            z-index: 2000;
            align-items: center;
            justify-content: center;
        }
        
        .lightbox.active {
            display: flex;
        }
        
        .lightbox img {
            max-width: 90%;
            max-height: 90%;
            object-fit: contain;
            cursor: grab; /* Add grab cursor for panning */
            transform-origin: center center; /* Ensure zoom is centered initially */
            transition: transform 0.1s ease-out; /* Smooth out zoom/pan a bit */
        }
        
        .lightbox-controls {
            position: absolute;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(0, 0, 0, 0.5);
            padding: 10px;
            border-radius: 5px;
            display: flex;
            gap: 10px;
            z-index: 2020; /* Above image, below close button if it overlaps */
        }

        .lightbox-controls button {
            background-color: rgba(255, 255, 255, 0.2);
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.3);
            padding: 8px 15px;
            border-radius: 5px; /* Changed from 3px to 5px */
            cursor: pointer;
            font-size: 0.9rem;
        }

        .lightbox-controls button:hover {
            background-color: rgba(255, 255, 255, 0.3);
        }
        
        /* PDF viewer */
        .pdf-viewer {
            width: 95%;
            height: 90%;
            max-width: 1400px;
            background: white;
            border-radius: 10px;
            overflow: hidden;
        }
        
        .pdf-viewer iframe {
            width: 100%;
            height: 100%;
            border: none;
        }
        
        /* Text viewer */
        .text-viewer {
            width: 95%;
            height: 90%;
            max-width: 1200px;
            background: var(--bg-primary);
            border-radius: 10px;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        
        .text-viewer-header {
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .text-viewer-content {
            flex: 1;
            overflow: auto;
            padding: 1rem;
        }
        
        .text-viewer pre {
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9rem;
            line-height: 1.5;
        }
        
        .markdown-content {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
        }
        
        .markdown-content h1, .markdown-content h2, .markdown-content h3 {
            margin-top: 1.5rem;
            margin-bottom: 0.5rem;
        }
        
        .markdown-content code {
            background: var(--bg-tertiary);
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-size: 0.9em;
        }
        
        .markdown-content pre {
            background: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 5px;
            overflow-x: auto;
        }
        
        .markdown-content pre code {
            background: none;
            padding: 0;
        }
        
        .markdown-content blockquote {
            border-left: 4px solid var(--accent-color);
            padding-left: 1rem;
            margin: 1rem 0;
            color: var(--text-secondary);
        }
        
        /* Video player */
        .video-player {
            max-width: 90%;
            max-height: 90%;
        }
        
        .video-player video {
            max-width: 100%;
            max-height: 90vh;
            border-radius: 10px;
        }
        
        /* Audio player */
        .audio-player {
            background: var(--bg-primary);
            border-radius: 10px;
            padding: 2rem;
            text-align: center;
            max-width: 500px;
        }
        
        .audio-player h3 {
            margin-bottom: 1.5rem;
            color: var(--text-primary);
        }
        
        .audio-player audio {
            width: 100%;
            margin-top: 1rem;
        }
        
        .audio-icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
        
        /* ZIP viewer */
        .zip-viewer {
            width: 95%;
            height: 90%;
            max-width: 1000px;
            background: var(--bg-primary);
            border-radius: 10px;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        
        .zip-viewer-header {
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
        }
        
        .zip-viewer-content {
            flex: 1;
            overflow: auto;
            padding: 1rem;
        }
        
        .zip-file-list {
            list-style: none;
        }
        
        .zip-file-item {
            padding: 0.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .zip-file-item:last-child {
            border-bottom: none;
        }
        
        .zip-file-name {
            flex: 1;
            word-break: break-all;
        }
        
        .zip-file-size {
            color: var(--text-secondary);
            font-size: 0.875rem;
            margin-left: 1rem;
        }
        
        .empty-state {
            text-align: center;
            padding: 4rem;
            color: var(--text-secondary);
        }
        
        .empty-state h3 {
            margin-bottom: 1rem;
        }
        
        .allowed-types {
            background: var(--bg-primary);
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 1rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
            display: none; /* Hide by default */
        }
        
        .allowed-types strong {
            color: var(--text-primary);
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .header {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }
            
            .controls {
                flex-direction: column;
                gap: 1rem;
            }
            
            .controls-left {
                width: 100%;
                justify-content: center;
            }
            
            .sort-controls {
                width: 100%;
            }
            
            .sort-select {
                width: 100%;
            }
            
            .icon-view {
                grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            }
            
            .progress-container {
                left: 1rem;
                right: 1rem;
                width: auto;
            }
            
            .file-actions {
                flex-direction: row;
                gap: 0.5rem;
                position: static;
                transform: none;
                box-shadow: none;
                background: transparent;
                padding: 0;
                margin-left: auto; /* Push actions to the right in flex item */
            }
            .file-item { /* Ensure actions are visible on mobile */
                 flex-wrap: wrap;
            }
            .file-info {
                padding-right: 0;
                 flex-basis: calc(100% - 100px); /* Give space for actions */
                 margin-bottom: 0.5rem; /* Space if actions wrap */
            }
             .file-actions {
                position: relative; /* Simpler positioning for mobile */
                flex-basis: 100px; /* Ensure actions have space */
                justify-content: flex-end;
             }

            
            .text-viewer, .pdf-viewer, .zip-viewer {
                width: 95%;
                height: 95%;
            }

            /* Hide lightbox title on mobile */
            #lightbox .preview-title {
                display: none;
            }
            /* Hide video modal title on mobile */
            #videoModal .preview-title {
                display: none;
            }
        }

        #breadcrumbNav {
            padding: 0.5rem 1rem; 
            background: var(--bg-tertiary); 
            border-bottom: 1px solid var(--border-color); 
            border-radius: 5px 5px 0 0; 
            display: none; /* Initially hidden */
            margin-bottom: 1rem; /* Added padding below breadcrumbs */
        }

        [data-theme="dark"] #createFolderBtn {
            /* color: #ffffff; */ /* Reverting to inherit from .btn-secondary which is already white */
            /* background-color: #555555; */ /* No longer needed with text plus */
            /* border-color: #666666; */ /* No longer needed */
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><?php echo htmlspecialchars($SITE_TITLE); ?></h1>
            <div class="header-controls">
                <button class="btn btn-secondary icon-btn" id="toggleAllowedTypesBtn" onclick="toggleAllowedTypesInfo()" title="Toggle allowed file types info" style="font-size: 1rem;">ℹ️</button>
                <button class="theme-toggle" onclick="toggleTheme()">🌙 Dark</button>
                <button class="btn btn-secondary" onclick="handleLogout()" title="Logout" style="padding: 0.5rem 1rem;">🚪 Log Out</button>  <!-- Ensure this button is present -->
            </div>
        </div>
        
        <div class="allowed-types" id="allowedTypesInfo" style="display: none;">
            <strong>Allowed file types:</strong> Images (jpg, png, gif, webp, svg), Documents (pdf, doc, docx, txt, md), Spreadsheets (xls, xlsx, csv), Archives (zip, rar, 7z), Media (mp3, wav, ogg, m4a, mp4, avi, mov, webm, mkv), Text files (json, xml, html, css, js, log). 
            <strong>Max file size:</strong> <?php echo ($MAX_FILE_SIZE / 1024 / 1024); ?>MB
        </div>
        
        <div class="storage-progress-container" style="margin-bottom: 1.5rem; background: var(--bg-primary); padding: 1rem; border-radius: 10px; box-shadow: 0 2px 10px var(--shadow);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                <span style="font-size: 0.9rem; color: var(--text-primary);">Storage Usage</span>
                <span id="storageUsageText" style="font-size: 0.9rem; color: var(--text-secondary);"></span>
            </div>
            <div class="progress-bar" style="height: 15px;">
                <div id="storageUsageFill" class="progress-fill" style="width: 0%; height: 15px; background-color: var(--accent-color);"></div>
            </div>
        </div>

        <div class="upload-area" id="uploadArea">
            <h3>Upload Files</h3>
            <p>Drag and drop files here or click to browse</p>
            <input type="file" id="fileInput" class="file-input" multiple>
            <button class="btn" onclick="document.getElementById('fileInput').click()">Choose Files</button>
        </div>
        
        <div class="controls">
            <div class="controls-left" style="gap: 1rem;">
                <button class="btn btn-secondary" id="toggleSelectionModeBtn" onclick="toggleSelectionMode()" title="Select">☐</button>
                <div id="selectAllContainer" style="display: none; align-items: center; gap: 0.5rem;">
                    <input type="checkbox" id="selectAllCheckbox" onchange="toggleSelectAll(this.checked)" style="width: 18px; height: 18px; cursor: pointer;">
                    <label for="selectAllCheckbox" style="font-size: 0.875rem; color: var(--text-secondary); cursor: pointer;">Select All</label>
                </div>
                <div class="view-toggle">
                    <button class="view-btn active" onclick="setView('list')" title="List View">☰</button>
                    <button class="view-btn" onclick="setView('icon')" title="Icon View">🖼️</button>
                </div>
                <div class="sort-controls">
                    <label style="font-size: 0.875rem; color: var(--text-secondary);">Sort by:</label>
                    <select class="sort-select" id="sortSelect" onchange="handleSort()">
                        <option value="date-desc">Date (Newest First)</option>
                        <option value="date-asc">Date (Oldest First)</option>
                        <option value="name-asc">Name (A-Z)</option>
                        <option value="name-desc">Name (Z-A)</option>
                        <option value="size-desc">Size (Largest First)</option>
                        <option value="size-asc">Size (Smallest First)</option>
                    </select>
                </div>
            </div>
            <div>
                <?php if ($ALLOW_FILE_DELETION): ?>
                <button class="btn btn-danger" id="deleteSelectedBtn" onclick="deleteSelectedFiles()" style="display: none; margin-right: 0.5rem;">🗑️ Delete Selected</button>
                <?php endif; ?>
                <button class="btn btn-secondary" id="downloadSelectedBtn" onclick="downloadSelectedFiles()" style="display: none; margin-right: 0.5rem;">📥 Download Selected</button>
                <button class="btn btn-secondary" id="createFolderBtn" onclick="handleCreateFolderClick()" title="Create New Folder" style="margin-right: 0.5rem;">+ 📁</button> 
                <button class="btn" onclick="downloadAll()">📥 Download All</button>
            </div>
        </div>

        <div class="files-container">
            <div id="breadcrumbNav" style="padding: 0.5rem 1rem; background: var(--bg-tertiary); border-bottom: 1px solid var(--border-color); border-radius: 5px 5px 0 0; display: none;"></div>
            <div id="listView" class="list-view active"></div>
            <div id="iconView" class="icon-view"></div>
            <div id="emptyState" class="empty-state" style="display: none;">
                <h3>No files uploaded yet</h3>
                <p>Start by uploading some files using the area above</p>
            </div>
        </div>
    </div>
    
    <div class="progress-container" id="progressContainer"></div>
    
    <div class="lightbox" id="lightbox" onclick="closeLightbox(event)">
        <button class="preview-close" onclick="closeLightbox(event)">×</button>
        <div class="preview-title" id="lightboxTitle"></div>
        <img id="lightboxImage" src="" alt="Preview Image">
        <div class="lightbox-controls">
            <button onclick="lightboxZoomIn(event)" title="Zoom In">+</button>
            <button onclick="lightboxZoomOut(event)" title="Zoom Out">-</button>
            <button onclick="lightboxResetZoom(event)" title="Reset Zoom">Reset</button>
        </div>
    </div>
    
    <div class="preview-modal" id="pdfModal">
        <button class="preview-close" onclick="closePdfViewer()">×</button>
        <div class="preview-title" id="pdfTitle"></div>
        <div class="pdf-viewer">
            <iframe id="pdfFrame" src=""></iframe>
        </div>
    </div>
    
    <div class="preview-modal" id="textModal">
        <button class="preview-close" onclick="closeTextViewer()">×</button>
        <div class="text-viewer">
            <div class="text-viewer-header">
                <h3 id="textTitle"></h3>
                <button class="btn btn-secondary" onclick="downloadCurrentFile()">Download</button>
            </div>
            <div class="text-viewer-content" id="textContent"></div>
        </div>
    </div>
    
    <div class="preview-modal" id="videoModal" onclick="closeVideoPlayer(event, true)">
        <button class="preview-close" onclick="closeVideoPlayer(event, false)">×</button>
        <div class="preview-title" id="videoTitle"></div>
        <div class="video-player">
            <video id="videoPlayer" controls playsinline webkit-playsinline></video>
        </div>
    </div>
    
    <div class="preview-modal" id="audioModal">
        <button class="preview-close" onclick="closeAudioPlayer()">×</button>
        <div class="audio-player">
            <div class="audio-icon">🎵</div>
            <h3 id="audioTitle"></h3>
            <audio id="audioPlayer" controls></audio>
        </div>
    </div>
    
    <div class="preview-modal" id="zipModal">
        <button class="preview-close" onclick="closeZipViewer()">×</button>
        <div class="zip-viewer">
            <div class="zip-viewer-header">
                <h3 id="zipTitle"></h3>
                <p id="zipInfo"></p>
            </div>
            <div class="zip-viewer-content">
                <ul class="zip-file-list" id="zipContents"></ul>
            </div>
        </div>
    </div>
    
    <script>
        let currentView = 'list';
        let uploadQueue = [];
        let isUploading = false;
        let currentPreviewFile = null;
        let selectedFiles = []; // Array to store names of selected files
        const csrfToken = '<?php echo $_SESSION['csrf_token']; ?>';
        const allowFileDeletion = <?php echo json_encode($ALLOW_FILE_DELETION); ?>;
        const maxFileSize = <?php echo $MAX_FILE_SIZE; ?>; // Pass MAX_FILE_SIZE to JS
        let isSelectionModeActive = false;
        let currentDirectoryPath = ''; // Variable to store the current path
        
        // Lightbox zoom/pan state
        let lightboxZoomLevel = 1;
        let lightboxIsPanning = false;
        let lightboxStartX = 0;
        let lightboxStartY = 0;
        let lightboxTranslateX = 0;
        let lightboxTranslateY = 0;
        let lightboxImageElement = null;

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            loadFiles(); // Load files with default sort
            setupDragDrop();
            setupFileInput();
            updateStorageUsageDisplay(); // Initial call for storage usage
            initializeTheme();
            updateActionButtons(); // Ensure action buttons are correctly hidden initially
        });
        
        // Initialize theme based on OS preference or saved preference
        function initializeTheme() {
            const savedTheme = localStorage.getItem('theme');
            
            if (savedTheme) {
                document.documentElement.setAttribute('data-theme', savedTheme);
            } else {
                // Check OS preference
                const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                document.documentElement.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
            }
            
            updateThemeButton();
            
            // Listen for OS theme changes
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
                // If OS theme changes, update the site theme and persist this change.
                // This ensures the site automatically reflects OS changes, even if a manual
                // toggle was used previously.
                const newTheme = e.matches ? 'dark' : 'light';
                document.documentElement.setAttribute('data-theme', newTheme);
                localStorage.setItem('theme', newTheme); // Persist the OS-driven theme change
                updateThemeButton();
            });
        }
        
        // Update theme button text
        function updateThemeButton() {
            const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
            const button = document.querySelector('.theme-toggle');
            if (button) {
                // button.textContent = currentTheme === 'dark' ? '☀️ Light' : '🌙 Dark';
                // Update to reflect the current state as per user request:
                button.textContent = currentTheme === 'dark' ? '🌙 Dark' : '☀️ Light';
            }
        }
        
        // Theme toggle
        function toggleTheme() {
            const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateThemeButton();
        }
        
        // View toggle
        function setView(view) {
            currentView = view;
            document.querySelectorAll('.view-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.list-view, .icon-view').forEach(v => v.classList.remove('active'));
            
            const listViewEl = document.getElementById('listView');
            const iconViewEl = document.getElementById('iconView');

            if (view === 'list') {
                document.querySelector('.view-btn:first-child').classList.add('active');
                if(listViewEl) listViewEl.classList.add('active');
            } else {
                document.querySelector('.view-btn:last-child').classList.add('active');
                if(iconViewEl) iconViewEl.classList.add('active');
            }
            updateFileCheckboxesState(); // Ensure visual selection is consistent after view switch
        }
        
        // Setup drag and drop
        function setupDragDrop() {
            const uploadArea = document.getElementById('uploadArea');
            if (!uploadArea) return;

            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                uploadArea.addEventListener(eventName, preventDefaults, false);
                document.body.addEventListener(eventName, (e) => { // Prevent drops outside area
                    if (e.target !== uploadArea && !uploadArea.contains(e.target)) {
                        preventDefaults(e);
                    }
                }, false);
            });
            
            ['dragenter', 'dragover'].forEach(eventName => {
                uploadArea.addEventListener(eventName, () => uploadArea.classList.add('dragover'), false);
            });
            
            ['dragleave', 'drop'].forEach(eventName => {
                uploadArea.addEventListener(eventName, () => uploadArea.classList.remove('dragover'), false);
            });
            
            uploadArea.addEventListener('drop', handleDrop, false);
        }
        
        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }
        
        function handleDrop(e) {
            const dt = e.dataTransfer;
            const items = dt.items;
            const filesToUpload = []; // Temp array to collect all files with their paths
            let promises = [];

            if (items && items.length) {
                for (let i = 0; i < items.length; i++) {
                    const item = items[i].webkitGetAsEntry(); // Try to get as a FileSystemEntry
                    if (item) {
                        promises.push(traverseFileTree(item, '', filesToUpload));
                    }
                }

                Promise.all(promises).then(() => {
                    // Now filesToUpload is populated with { file: FileObject, path: "relative/path/to/file.ext" }
                    uploadQueue.push(...filesToUpload); // Add all collected files to the main queue
                    processUploadQueue();
                    document.getElementById('uploadArea').classList.remove('dragover');
                }).catch(err => {
                    console.error("Error processing dropped items:", err);
                    document.getElementById('uploadArea').classList.remove('dragover');
                });
            } else {
                // Fallback for browsers that don't support getAsEntry or if no items found
                handleFiles(dt.files); 
                document.getElementById('uploadArea').classList.remove('dragover');
            }
        }

        // Recursive function to traverse directories and collect files
        function traverseFileTree(entry, path, filesToUpload) {
            return new Promise((resolve, reject) => {
                if (entry.isFile) {
                    entry.file(file => {
                        // Client-side check for file size before adding to queue
                        if (file.size > maxFileSize) {
                            alert(`File '${path + file.name}' exceeds the maximum allowed size of ${formatFileSize(maxFileSize)}.`);
                            resolve(); // Resolve even if skipped, to not break Promise.all
                            return;
                        }
                        filesToUpload.push({ file: file, path: path + file.name });
                        resolve();
                    }, err => {
                        console.error("Could not get file from entry: ", err);
                        reject(err); 
                    });
                } else if (entry.isDirectory) {
                    let dirReader = entry.createReader();
                    let allEntries = [];
                    
                    const readEntries = () => {
                        dirReader.readEntries(entries => {
                            if (!entries.length) {
                                // All entries read, now process them
                                Promise.all(allEntries.map(e => traverseFileTree(e, path + entry.name + '/', filesToUpload)))
                                    .then(resolve)
                                    .catch(reject);
                            } else {
                                allEntries = allEntries.concat(Array.from(entries));
                                readEntries(); // Read more entries if available
                            }
                        }, err => {
                            console.error("Could not read directory entries: ", err);
                            reject(err);
                        });
                    };
                    readEntries(); // Start reading directory entries
                }
            });
        }
        
        // Setup file input
        function setupFileInput() {
            const fileInput = document.getElementById('fileInput');
            if(fileInput) {
                fileInput.addEventListener('change', (e) => {
                    handleFiles(e.target.files);
                     e.target.value = null; // Reset file input for same file selection
                });
            }
        }
        
        // Handle files
        function handleFiles(files) {
            ([...files]).forEach(file => {
                // Client-side check for file size before adding to queue
                if (file.size > maxFileSize) {
                    alert(`File '${file.name}' exceeds the maximum allowed size of ${formatFileSize(maxFileSize)}.`);
                    return; // Skip this file
                }
                // For files selected via input, path is just the filename (no folder structure)
                uploadQueue.push({ file: file, path: file.name }); 
            });
            processUploadQueue();
        }
        
        // Process upload queue
        async function processUploadQueue() {
            if (isUploading || uploadQueue.length === 0) return;
            
            isUploading = true;
            // const file = uploadQueue.shift(); // Old: just file object
            const queueItem = uploadQueue.shift(); // New: { file: FileObject, path: "relative/path/filename.ext" }
            const file = queueItem.file;
            const clientRelativePath = queueItem.path; // This is the path relative to the dropped folder, or just filename
            const overwriteAction = queueItem.overwriteAction || null; // Get overwrite action if set
            const userSuggestedName = queueItem.userSuggestedName || null; // Get user suggested name if set

            const progressId = 'progress_' + Date.now() + Math.random().toString(36).substring(2,7);
            const progressHtml = `
                <div class="progress-item" id="${progressId}">
                    <h4>${escapeHtml(file.name)}</h4>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: 0%"></div>
                    </div>
                    <p class="progress-status" style="font-size:0.8em; color:var(--text-secondary); margin-top:0.3em;">Starting...</p>
                </div>
            `;
            document.getElementById('progressContainer')?.insertAdjacentHTML('beforeend', progressHtml);
            
            const formData = new FormData();
            formData.append('action', 'upload');
            formData.append('csrf_token', csrfToken);
            formData.append('file', file);
            formData.append('intendedSubPath', clientRelativePath); 
            formData.append('currentDirectoryPath', currentDirectoryPath); 
            if (overwriteAction) {
                formData.append('overwrite_action', overwriteAction);
            }
            if (userSuggestedName) { // Send userSuggestedName if provided
                formData.append('userSuggestedName', userSuggestedName);
            }
            
            try {
                const xhr = new XMLHttpRequest();
                const progressItemEl = document.getElementById(progressId);
                const progressBarFill = progressItemEl?.querySelector('.progress-fill');
                const progressStatus = progressItemEl?.querySelector('.progress-status');

                xhr.upload.addEventListener('progress', (e) => {
                    if (e.lengthComputable) {
                        const percentComplete = (e.loaded / e.total) * 100;
                        if(progressBarFill) progressBarFill.style.width = percentComplete + '%';
                        if(progressStatus) progressStatus.textContent = `${formatFileSize(e.loaded)} / ${formatFileSize(e.total)} (${percentComplete.toFixed(0)}%)`;
                    }
                });
                
                xhr.addEventListener('load', () => {
                    let requestHandled = false; 
                    let uploadActuallySuccessful = false;
                    let jsonData = null; // To store parsed result for use in setTimeout

                    if (xhr.status === 200) {
                        try {
                            jsonData = JSON.parse(xhr.responseText);
                            if (jsonData.success === true) {
                                if(progressStatus) progressStatus.textContent = 'Upload successful!';
                                if(progressBarFill) progressBarFill.style.backgroundColor = 'var(--accent-color)';
                                loadFiles(); 
                                updateStorageUsageDisplay(); 
                                requestHandled = true;
                                uploadActuallySuccessful = true;
                            } else if (jsonData.success === 'conflict') {
                                if (window.confirm(jsonData.message + "\n\nWould you like to replace the existing file?")) {
                                    uploadQueue.unshift({...queueItem, overwriteAction: 'replace' }); 
                                } else {
                                    // User chose NOT to replace, prompt for a new name or use server rename
                                    let suggestedName = jsonData.filename;
                                    const parts = jsonData.filename.split('.');
                                    if (parts.length > 1) {
                                        const ext = parts.pop();
                                        suggestedName = parts.join('.') + ' (1).' + ext;
                                    } else {
                                        suggestedName = jsonData.filename + ' (1)';
                                    }

                                    const userNewName = window.prompt(
                                        "File '" + jsonData.filename + "' already exists.\nEnter a new name for the uploaded file, or leave as is to have the server rename it (e.g., to '" + suggestedName + "').", 
                                        suggestedName
                                    );

                                    if (userNewName === null) { // User pressed Cancel on the prompt
                                        if(progressStatus) progressStatus.textContent = 'Upload cancelled for: ' + file.name;
                                        if(progressBarFill) progressBarFill.style.backgroundColor = 'var(--danger-color)';
                                        // setTimeout for removal will be handled below by !requestHandled logic
                                    } else if (userNewName.trim() === "") { // User cleared the name and pressed OK - treat as server rename
                                        uploadQueue.unshift({...queueItem, overwriteAction: 'rename' }); 
                                    } else { // User entered a new name or accepted suggestion
                                        uploadQueue.unshift({...queueItem, overwriteAction: 'rename', userSuggestedName: userNewName.trim() }); 
                                    }
                                }
                                progressItemEl?.remove(); 
                                requestHandled = true; 
                            } else { 
                                alert('Upload failed: ' + (jsonData.error || 'Unknown error'));
                                if(progressStatus) progressStatus.textContent = 'Error: ' + (jsonData.error || 'Unknown');
                                if(progressBarFill) progressBarFill.style.backgroundColor = 'var(--danger-color)';
                                requestHandled = true;
                            }
                        } catch (e) { 
                            alert('Upload failed: Invalid server response. ' + e.message);
                            if(progressStatus) progressStatus.textContent = 'Error: Invalid server response';
                            if(progressBarFill) progressBarFill.style.backgroundColor = 'var(--danger-color)';
                            requestHandled = true;
                        }
                    } else { 
                         alert('Upload failed: Server returned status ' + xhr.status);
                         if(progressStatus) progressStatus.textContent = 'Error: Server status ' + xhr.status;
                         if(progressBarFill) progressBarFill.style.backgroundColor = 'var(--danger-color)';
                         requestHandled = true; 
                    }

                    // Cleanup and next step
                    if (!requestHandled || (jsonData && jsonData.success !== 'conflict')) {
                        // If it was a normal success/failure (not a conflict that re-queues and handles its own progress bar removal)
                        setTimeout(() => {
                            progressItemEl?.remove();
                        }, uploadActuallySuccessful ? 2000 : 5000);
                    } // else, if it was a conflict, progressItemEl was already removed or will be handled by cancel timeout
                    
                    isUploading = false;
                    processUploadQueue(); 
                });
                
                xhr.addEventListener('error', () => {
                    alert('Upload failed: Network error');
                    if(progressStatus) progressStatus.textContent = 'Error: Network issue';
                    if(progressBarFill) progressBarFill.style.backgroundColor = 'var(--danger-color)';
                    setTimeout(() => progressItemEl?.remove(), 5000);
                    isUploading = false;
                    processUploadQueue();
                });
                
                xhr.open('POST', '', true); // Async true
                xhr.send(formData);
                
            } catch (error) {
                console.error('Upload error:', error);
                document.getElementById(progressId)?.remove();
                isUploading = false;
                processUploadQueue();
            }
        }

        // *** NEW FUNCTION: handleSort ***
        function handleSort() {
            const sortSelect = document.getElementById('sortSelect');
            if (sortSelect) {
                 const selectedValue = sortSelect.value;
                 const [sortBy, sortOrder] = selectedValue.split('-');
                 loadFiles(sortBy, sortOrder);
            }
        }
        
        // *** MODIFIED FUNCTION: loadFiles ***
        async function loadFiles(sortBy = 'date', sortOrder = 'desc', path = currentDirectoryPath) {
            const formData = new FormData();
            formData.append('action', 'list');
            formData.append('csrf_token', csrfToken);
            formData.append('sortBy', sortBy);
            formData.append('sortOrder', sortOrder);
            formData.append('currentPath', path); // Send current path to backend
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const result = await response.json();
                if (result.success) {
                    currentDirectoryPath = result.currentPath; // Update current path from server response
                    displayFiles(result.files, result.currentPath);
                    updateBreadcrumbs(result.currentPath);
                } else {
                    console.error('Error from server while listing files:', result.error);
                    alert('Could not load files: ' + (result.error || 'Unknown server error'));
                }
            } catch (error) {
                console.error('Error loading files:', error);
                alert('Could not load files. Check console for details.');
            }
        }
        
        function updateBreadcrumbs(path) {
            const breadcrumbNav = document.getElementById('breadcrumbNav');
            if (!breadcrumbNav) return;

            if (path === '' || path === null || path === undefined) {
                breadcrumbNav.style.display = 'none';
                breadcrumbNav.innerHTML = '';
                return;
            }

            breadcrumbNav.style.display = 'block';
            breadcrumbNav.innerHTML = ''; // Clear previous breadcrumbs

            const segments = path.split('/').filter(segment => segment !== '');
            let currentPathForLink = '';

            // Add Root link
            const rootLink = document.createElement('a');
            rootLink.href = '#';
            rootLink.textContent = 'Root';
            rootLink.style.textDecoration = 'none';
            rootLink.style.color = 'var(--accent-color)';
            rootLink.onclick = (e) => {
                e.preventDefault();
                currentDirectoryPath = '';
                loadFiles();
            };
            breadcrumbNav.appendChild(rootLink);

            segments.forEach((segment, index) => {
                const separator = document.createElement('span');
                separator.textContent = ' / ';
                separator.style.margin = '0 0.25rem';
                separator.style.color = 'var(--text-secondary)';
                breadcrumbNav.appendChild(separator);

                currentPathForLink += (currentPathForLink ? '/' : '') + segment;
                if (index === segments.length - 1) { // Last segment is current folder, not a link
                    const currentFolderText = document.createElement('span');
                    currentFolderText.textContent = escapeHtml(segment);
                    currentFolderText.style.color = 'var(--text-primary)';
                    breadcrumbNav.appendChild(currentFolderText);
                } else {
                    const segmentLink = document.createElement('a');
                    segmentLink.href = '#';
                    segmentLink.textContent = escapeHtml(segment);
                    segmentLink.style.textDecoration = 'none';
                    segmentLink.style.color = 'var(--accent-color)';
                    const pathForThisLink = currentPathForLink; // Capture path for this link's closure
                    segmentLink.onclick = (e) => {
                        e.preventDefault();
                        currentDirectoryPath = pathForThisLink;
                        loadFiles();
                    };
                    breadcrumbNav.appendChild(segmentLink);
                }
            });
        }
        
        // Display files
        function displayFiles(files, path) { // path parameter added
            const listView = document.getElementById('listView');
            const iconView = document.getElementById('iconView');
            const emptyState = document.getElementById('emptyState');

            if (!listView || !iconView || !emptyState) {
                console.error("Display elements not found!");
                return;
            }
            
            if (files.length === 0) {
                listView.innerHTML = '';
                iconView.innerHTML = '';
                emptyState.style.display = 'block';
                return;
            }
            
            emptyState.style.display = 'none';
            
            // List view
            listView.innerHTML = files.map(file => {
                const rawFileName = file.name;

                // 1. For HTML text display (titles, alt text)
                const escapedHtmlName = escapeHtml(rawFileName);

                // 2. For JavaScript string literals representing the raw filename (e.g., for preview titles, IDs)
                const jsEscapedRawFileName = escapeJs(rawFileName);

                // 3. For constructing actual URLs (hrefs, src attributes for direct media loading)
                //    Ensure single quotes are also encoded.
                const fullyUrlEncodedRawFileName = encodeURIComponent(rawFileName).replace(/'/g, "%27");

                // 4. Actual URLs for file operations
                const mediaFileResourceUrl = 'files/' + fullyUrlEncodedRawFileName;
                const downloadFileHref = `?download=${fullyUrlEncodedRawFileName}`;

                // 5. Arguments for JS functions in onclick handlers
                //    If an arg is a URL, JS-escape the fully formed URL string.
                //    If an arg is a raw name, JS-escape the raw name string.
                const jsArgMediaUrl = escapeJs(mediaFileResourceUrl);
                const jsArgRawFileName = jsEscapedRawFileName; // Already JS-escaped

                let clickHandler = '';
                let videoOverlayHtml = '';
                
                if (file.isDirectory) {
                    const dirPath = escapeJs((path ? path + '/' : '') + file.name);
                    clickHandler = `navigateToDirectory(\'${dirPath}\')`;
                } else if (file.canPreview) {
                    // Construct full relative path for file source URLs
                    const fileRelativePath = (path ? path + '/' : '') + file.name;
                    const fullyUrlEncodedFile = encodeURIComponent(fileRelativePath).replace(/'/g, "%27");
                    const jsArgMediaUrl = escapeJs('files/' + fullyUrlEncodedFile);
                    const jsArgRawFileName = escapeJs(fileRelativePath); // Send relative path for previews/ops

                    switch (file.previewType) {
                        case 'image':
                            clickHandler = `openLightbox(\'${jsArgMediaUrl}\', \'${jsArgRawFileName}\')`;
                            break;
                        case 'video':
                            clickHandler = `openVideoPlayer(\'${jsArgMediaUrl}\', \'${jsArgRawFileName}\')`;
                            if (file.hasThumb) {
                                videoOverlayHtml = '<div class="video-thumb-overlay">▶</div>';
                            }
                            break;
                        case 'pdf':
                            clickHandler = `openPdfViewer(\'${jsArgMediaUrl}\', \'${jsArgRawFileName}\')`;
                            break;
                        case 'text':
                            clickHandler = `openTextViewer(\'${jsArgRawFileName}\')`; 
                            break;
                        case 'audio':
                            clickHandler = `openAudioPlayer(\'${jsArgMediaUrl}\', \'${jsArgRawFileName}\')`;
                            break;
                        case 'zip':
                            clickHandler = `openZipViewer(\'${jsArgRawFileName}\')`; 
                            break;
                        default:
                            clickHandler = `window.location.href=\'?download=${fullyUrlEncodedFile}\'`
                    }
                } else { // Not a directory and cannot preview -> direct download
                    const fileRelativePath = (path ? path + '/' : '') + file.name;
                    const fullyUrlEncodedFile = encodeURIComponent(fileRelativePath).replace(/'/g, "%27");
                    clickHandler = `window.location.href=\'?download=${fullyUrlEncodedFile}\'`;
                }
                
                let thumbFileNameComponent = file.name;
                let thumbBaseDir = (path ? path + '/' : '');
                if (!file.isDirectory && (file.previewType === 'video' || file.previewType === 'pdf') && file.hasThumb) {
                    thumbFileNameComponent += '.jpg';
                }
                // Thumbnails are always relative to the root of THUMBS_DIR, mirroring structure
                const fullyEncodedThumbNamePart = encodeURIComponent(thumbBaseDir + thumbFileNameComponent).replace(/'/g, "%27");
                const thumbSrcAttributeValue = `files/thumbs/${fullyEncodedThumbNamePart}?m=${file.modified}`;

                const itemIdentifier = escapeJs((path ? path + '/' : '') + file.name); // Used for data-filename and checkbox value

                return `
                    <div class="file-item" data-filename="${itemIdentifier}">
                        <div style="display: flex; align-items: center; margin-right: 10px;">
                            <input type="checkbox" class="file-checkbox" value="${itemIdentifier}" onchange="handleFileSelectionChange()" style="width: 18px; height: 18px; cursor: pointer;">
                        </div>
                        <div class="file-info" onclick="${clickHandler}" title="${file.isDirectory ? 'Open folder' : 'Click to preview'} ${escapedHtmlName}">
                            <div class="file-icon ${!file.isDirectory && file.canPreview ? 'has-preview' : ''}">
                                ${file.isDirectory ? getFileIcon(null, 'folder') :
                                    (file.hasThumb ? 
                                        `<img src="${thumbSrcAttributeValue}" alt="${escapedHtmlName}" loading="lazy">` :
                                        getFileIcon(rawFileName, file.extension))
                                }
                                ${videoOverlayHtml} 
                            </div>
                            <div class="file-details">
                                <h4>${escapedHtmlName}</h4>
                                <p>${formatFileSize(file.size)}${file.isDirectory ? ' • Folder' : ' • ' + formatDate(file.modified)}</p>
                            </div>
                        </div>
                        <div class="file-actions">
                            <button class="btn btn-secondary icon-btn" onclick="event.stopPropagation(); handleRenameClick(\'${itemIdentifier}\', \'${escapeJs(rawFileName)}\')" title="Rename ${escapedHtmlName}">✏️</button>
                            <a href="${file.isDirectory ? '?download_folder=' + encodeURIComponent(itemIdentifier) : '?download=' + encodeURIComponent(itemIdentifier)}" class="btn btn-secondary icon-btn" title="Download ${escapedHtmlName}" onclick="event.stopPropagation()">↓</a>
                            ${(allowFileDeletion) ? `<button class="btn btn-danger icon-btn" onclick="event.stopPropagation(); deleteFile(\'${itemIdentifier}\')" title="Delete ${escapedHtmlName}">×</button>` : ''}
                        </div>
                    </div>
                `;
            }).join('');
            
            // Icon view
            iconView.innerHTML = files.map(file => {
                const rawFileName = file.name;
                const escapedHtmlName = escapeHtml(rawFileName);

                let previewHandler = '';
                let videoIconOverlayHtml = '';

                if (file.isDirectory) {
                    const dirPath = escapeJs((path ? path + '/' : '') + file.name);
                    previewHandler = `onclick="navigateToDirectory(\'${dirPath}\')"`;
                } else if (file.canPreview) {
                    const fileRelativePath = (path ? path + '/' : '') + file.name;
                    const fullyUrlEncodedFile = encodeURIComponent(fileRelativePath).replace(/'/g, "%27");
                    const jsArgMediaUrl = escapeJs('files/' + fullyUrlEncodedFile);
                    const jsArgRawFileName = escapeJs(fileRelativePath);

                    switch (file.previewType) {
                        case 'image':
                            previewHandler = `onclick="openLightbox(\'${jsArgMediaUrl}\', \'${jsArgRawFileName}\')"`;
                            break;
                        case 'video':
                            previewHandler = `onclick="openVideoPlayer(\'${jsArgMediaUrl}\', \'${jsArgRawFileName}\')"`;
                            if (file.hasThumb) {
                                videoIconOverlayHtml = '<div class="video-thumb-overlay">▶</div>';
                            }
                            break;
                        case 'pdf':
                            previewHandler = `onclick="openPdfViewer(\'${jsArgMediaUrl}\', \'${jsArgRawFileName}\')"`;
                            break;
                        case 'text':
                            previewHandler = `onclick="openTextViewer(\'${jsArgRawFileName}\')"`;
                            break;
                        case 'audio':
                            previewHandler = `onclick="openAudioPlayer(\'${jsArgMediaUrl}\', \'${jsArgRawFileName}\')"`;
                            break;
                        case 'zip':
                            previewHandler = `onclick="openZipViewer(\'${jsArgRawFileName}\')"`;
                            break;
                         default:
                            previewHandler = `onclick="window.location.href=\'?download=${fullyUrlEncodedFile}\'";`
                    }
                } else {
                    const fileRelativePath = (path ? path + '/' : '') + file.name;
                    const fullyUrlEncodedFile = encodeURIComponent(fileRelativePath).replace(/'/g, "%27");
                    previewHandler = `onclick="window.location.href=\'?download=${fullyUrlEncodedFile}\'"`;
                }

                let thumbFileNameComponent = file.name;
                let thumbBaseDir = (path ? path + '/' : '');
                if (!file.isDirectory && (file.previewType === 'video' || file.previewType === 'pdf') && file.hasThumb) {
                    thumbFileNameComponent += '.jpg';
                }
                const fullyEncodedThumbNamePart = encodeURIComponent(thumbBaseDir + thumbFileNameComponent).replace(/'/g, "%27");
                const thumbSrcAttributeValue = `files/thumbs/${fullyEncodedThumbNamePart}?m=${file.modified}`;
                
                const itemIdentifier = escapeJs((path ? path + '/' : '') + file.name); // Used for data-filename and checkbox value

                return `
                    <div class="file-card" data-filename="${itemIdentifier}">
                        <div style="position: absolute; top: 10px; left: 10px; z-index:1;">
                            <input type="checkbox" class="file-checkbox" value="${itemIdentifier}" onchange="handleFileSelectionChange()" style="width: 18px; height: 18px; cursor: pointer;">
                        </div>
                        <div class="file-preview" ${previewHandler} title="${file.isDirectory ? 'Open folder' : 'Click to preview'} ${escapedHtmlName}">
                            <div class="thumbnail-wrapper">
                                ${file.isDirectory ? `<div class="file-icon-large">${getFileIcon(null, 'folder')}</div>` :
                                    (file.hasThumb ? 
                                        `<img src="${thumbSrcAttributeValue}" alt="${escapedHtmlName}" loading="lazy">` :
                                        `<div class="file-icon-large">${getFileIcon(rawFileName, file.extension)}</div>`)
                                }
                                ${videoIconOverlayHtml}
                            </div>
                        </div>
                        <h4>${escapedHtmlName}</h4>
                        <p>${formatFileSize(file.size)}</p>
                        <div class="file-card-actions">
                             <button class="btn btn-secondary icon-btn" onclick="event.stopPropagation(); handleRenameClick(\'${itemIdentifier}\', \'${escapeJs(rawFileName)}\')" title="Rename ${escapedHtmlName}">✏️</button>
                             <a href="${file.isDirectory ? '?download_folder=' + encodeURIComponent(itemIdentifier) : '?download=' + encodeURIComponent(itemIdentifier)}" class="btn btn-secondary icon-btn" title="Download ${escapedHtmlName}">↓</a>
                            ${(allowFileDeletion) ? `<button class="btn btn-danger icon-btn" onclick="deleteFile(\'${itemIdentifier}\')" title="Delete ${escapedHtmlName}">×</button>` : ''}
                        </div>
                    </div>
                `;
            }).join('');
            // Re-apply current view setting in case elements were completely replaced
            setView(currentView);
            updateFileCheckboxesState(); // Reflect current selection on new checkboxes
            updateActionButtons(); // Update buttons based on current selection
        }
        
        // Delete file or folder
        async function deleteFile(itemIdentifier) { // itemIdentifier can be file or folder path
            // Try to determine if it's a folder based on the data we have in the DOM or itemIdentifier structure
            // This is a client-side heuristic. The server will make the final determination.
            let isLikelyFolder = false;
            const fileElement = document.querySelector(`[data-filename="${itemIdentifier.replace(/"/g, '\\"')}"]`);
            if (fileElement) {
                const detailsText = fileElement.querySelector('.file-details p')?.textContent;
                if (detailsText && detailsText.toLowerCase().includes('folder')) {
                    isLikelyFolder = true;
                } else if (!itemIdentifier.includes('.') && itemIdentifier.split('/').pop().indexOf('.') === -1) {
                    // No extension in the last part of the path could also indicate a folder
                    // This is less reliable than checking the displayed text
                    // Consider if there's a direct 'isDirectory' flag available on the element or from JS data if we restructure
                    // For now, if detailsText doesn't say Folder, and it has no obvious file extension, it *might* be a folder.
                    // This simple check might be enough if combined with the confirmation text.
                    const namePart = itemIdentifier.split('/').pop();
                    if (namePart.indexOf('.') === -1) isLikelyFolder = true; 
                }
            }

            let confirmMessage = `Are you sure you want to delete '${itemIdentifier}'?`;
            if (isLikelyFolder) {
                confirmMessage += '\n\nWARNING: This will delete the folder and ALL its contents!';
            }

            if (!confirm(confirmMessage)) return;
            
            const formData = new FormData();
            formData.append('action', 'delete');
            formData.append('csrf_token', csrfToken);
            formData.append('filename', itemIdentifier);
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                if (result.success) {
                    loadFiles(); // Reload files, applying current sort
                    updateStorageUsageDisplay(); // Update storage usage after delete
                } else {
                    alert('Delete failed: ' + (result.error || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error deleting file:', error);
                alert('Delete failed: Network error');
            }
        }
        
        // Download all
        function downloadAll() {
            window.location.href = '?download_all=1';
        }
        
        // Preview functions
        function openLightbox(imageSrcUrl, rawFileName) {
            currentPreviewFile = rawFileName;
            lightboxImageElement = document.getElementById('lightboxImage'); // Store reference
            const lightboxTitle = document.getElementById('lightboxTitle');
            const lightbox = document.getElementById('lightbox');

            if(lightboxImageElement) {
                // Reset previous transformations
                lightboxImageElement.style.transform = 'scale(1) translate(0px, 0px)';
                lightboxImageElement.style.transformOrigin = 'center center'; // Initial origin
                lightboxZoomLevel = 1;
                lightboxTranslateX = 0;
                lightboxTranslateY = 0;
                
                lightboxImageElement.src = imageSrcUrl + '?m=' + Date.now(); // Add cache buster
                lightboxImageElement.style.cursor = 'grab'; // Initial cursor

                // Add event listeners for zoom and pan
                lightbox.addEventListener('wheel', handleLightboxZoom);
                lightboxImageElement.addEventListener('mousedown', startLightboxPan);
                lightbox.addEventListener('mousemove', handleLightboxPan); // Listen on lightbox for mouse moving outside image
                lightbox.addEventListener('mouseup', endLightboxPan);
                lightbox.addEventListener('mouseleave', endLightboxPan); // End pan if mouse leaves lightbox
            }
            if(lightboxTitle) lightboxTitle.textContent = rawFileName;
            if(lightbox) lightbox.classList.add('active');
        }
        
        function closeLightbox(event) {
            // If event is passed and target is not the close button itself, check if it's the backdrop
            // if (event && event.target.id !== 'lightbox' && event.target.tagName !== 'BUTTON') return;
            
            const lightbox = document.getElementById('lightbox');
            const closeButton = lightbox.querySelector('.preview-close');

            if (event) { // If called by a click event
                if (event.target === lightboxImageElement || event.target.closest('.lightbox-controls')) {
                    // Click was on the image or the new controls, do not close.
                    if(event) event.stopPropagation(); // Prevent lightbox click handler from closing
                    return;
                }
                if (event.target !== lightbox && event.target !== closeButton) {
                    // Click was inside the lightbox but not on the backdrop or explicit close button.
                    return; 
                }
            }
            // Proceed to close if:
            // 1. No event (called by ESC key)
            // 2. Event target is the lightbox backdrop itself
            // 3. Event target is the close button

            if(lightbox) {
                lightbox.classList.remove('active');
                // Remove event listeners
                lightbox.removeEventListener('wheel', handleLightboxZoom);
                if (lightboxImageElement) {
                    lightboxImageElement.removeEventListener('mousedown', startLightboxPan);
                    lightboxImageElement.style.transform = 'scale(1) translate(0px, 0px)'; // Reset transform
                    lightboxImageElement.style.transformOrigin = 'center center'; // Reset origin
                    lightboxImageElement.style.cursor = 'grab';
                    lightboxImageElement.src = ''; // Clear image to free memory
                }
                lightbox.removeEventListener('mousemove', handleLightboxPan);
                lightbox.removeEventListener('mouseup', endLightboxPan);
                lightbox.removeEventListener('mouseleave', endLightboxPan);
            }
            
            currentPreviewFile = null;
            lightboxImageElement = null;
            lightboxZoomLevel = 1;
            lightboxIsPanning = false;
            lightboxTranslateX = 0;
            lightboxTranslateY = 0;

            if (event) event.stopPropagation(); // Prevent further bubbling if called from button
        }

        function handleLightboxZoom(event, customZoomLevel) {
            if (!lightboxImageElement) return;
            if(event) event.preventDefault();

            const zoomIntensity = 0.05; // Reduced sensitivity
            const minZoom = 0.5;
            const maxZoom = 5;
            
            // const lightbox = document.getElementById('lightbox'); // No longer needed for mouse relative to lightbox
            // const lightboxRect = lightbox.getBoundingClientRect();
            // let mouseXInLightbox = event.clientX - lightboxRect.left; 
            // let mouseYInLightbox = event.clientY - lightboxRect.top;

            // if (event && event.type !== 'wheel') { 
            //     mouseXInLightbox = lightboxRect.width / 2;
            //     mouseYInLightbox = lightboxRect.height / 2;
            // }

            const prevZoomLevel = lightboxZoomLevel;

            if (typeof customZoomLevel === 'number') {
                lightboxZoomLevel = customZoomLevel;
            } else if (event && event.deltaY < 0) { 
                lightboxZoomLevel = Math.min(lightboxZoomLevel + zoomIntensity, maxZoom);
            } else if (event && event.deltaY > 0) { 
                lightboxZoomLevel = Math.max(lightboxZoomLevel - zoomIntensity, minZoom);
            }

            // Always keep transform-origin center for centered zoom
            if (lightboxImageElement) lightboxImageElement.style.transformOrigin = 'center center';

            // If zoom level brings it back to 1x or less, reset any panning.
            if (lightboxZoomLevel <= 1) { 
                lightboxTranslateX = 0;
                lightboxTranslateY = 0;
            } 
            // When zooming (not from a button action that resets), maintain current pan if already panned.
            // The scaling will happen around the center of the currently panned view.
            // No explicit new translation calculation needed here for centered zoom relative to mouse.
            
            applyLightboxTransform();
        }

        function lightboxZoomIn(event) {
            if(event) event.stopPropagation(); 
            if (!lightboxImageElement) return;
            // Pass null for event to indicate it's a button click, handleLightboxZoom will use its default (centered) behavior
            handleLightboxZoom(null, Math.min(lightboxZoomLevel + 0.2, 5)); 
        }

        function lightboxZoomOut(event) {
            if(event) event.stopPropagation();
            if (!lightboxImageElement) return;
            handleLightboxZoom(null, Math.max(lightboxZoomLevel - 0.2, 0.5));
        }

        function lightboxResetZoom(event) {
            if(event) event.stopPropagation();
            if (!lightboxImageElement) return;
            // Ensure translation is also reset by handleLightboxZoom when level is 1
            handleLightboxZoom(null, 1); 
        }

        function startLightboxPan(event) {
            if (!lightboxImageElement || event.button !== 0) return; // Only pan with left mouse button
            if (lightboxZoomLevel <= 1) return; // No panning if not zoomed in

            event.preventDefault(); // Prevent image dragging behavior
            lightboxIsPanning = true;
            lightboxStartX = event.clientX - lightboxTranslateX;
            lightboxStartY = event.clientY - lightboxTranslateY;
            lightboxImageElement.style.cursor = 'grabbing';
        }

        function handleLightboxPan(event) {
            if (!lightboxIsPanning || !lightboxImageElement) return;
            event.preventDefault();
            
            lightboxTranslateX = event.clientX - lightboxStartX;
            lightboxTranslateY = event.clientY - lightboxStartY;
            
            applyLightboxTransform();
        }

        function endLightboxPan(event) {
            if (!lightboxImageElement) return;
            if (lightboxIsPanning) {
                 if (event) event.preventDefault();
            }
            lightboxIsPanning = false;
            if (lightboxZoomLevel > 1) {
                lightboxImageElement.style.cursor = 'grab';
            } else {
                lightboxImageElement.style.cursor = 'default'; // Or back to grab if we allow 1x pan
            }
        }

        function applyLightboxTransform() {
            if (!lightboxImageElement) return;
            // Constrain panning within reasonable bounds if needed, especially when zoomed in.
            // For now, allow free panning.
            lightboxImageElement.style.transform = `scale(${lightboxZoomLevel}) translate(${lightboxTranslateX}px, ${lightboxTranslateY}px)`;
        }
        
        function openPdfViewer(pdfSrcUrl, rawFileName) {
            currentPreviewFile = rawFileName;

            if (isMobileView()) {
                window.open(pdfSrcUrl, '_blank');
                currentPreviewFile = null; // Reset as we are not managing an open modal
                return;
            }
            
            const pdfFrame = document.getElementById('pdfFrame');
            // const pdfTitle = document.getElementById('pdfTitle'); // Title will not be set
            const pdfModal = document.getElementById('pdfModal');
            if(pdfFrame) pdfFrame.src = pdfSrcUrl;
            // if(pdfTitle) pdfTitle.textContent = rawFileName; // Do not set title
            if(pdfModal) pdfModal.classList.add('active');
        }
        
        function closePdfViewer() {
            const pdfModal = document.getElementById('pdfModal');
            const pdfFrame = document.getElementById('pdfFrame');
            if(pdfModal) pdfModal.classList.remove('active');
            if(pdfFrame) pdfFrame.src = ''; // Important for some browsers to stop loading/rendering
            currentPreviewFile = null;
        }
        
        async function openTextViewer(rawFileName) { // Filename is the primary identifier
            currentPreviewFile = rawFileName;
            const formData = new FormData();
            formData.append('action', 'preview_text');
            formData.append('csrf_token', csrfToken);
            formData.append('filename', rawFileName); // Send raw filename
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                const textTitle = document.getElementById('textTitle');
                const textContent = document.getElementById('textContent');
                const textModal = document.getElementById('textModal');

                if (result.success) {
                    if(textTitle) textTitle.textContent = rawFileName;
                    
                    if (textContent) {
                        if (result.extension === 'md') {
                            textContent.innerHTML = `<div class="markdown-content">${renderMarkdown(escapeHtml(result.content))}</div>`;
                        } else {
                            textContent.innerHTML = `<pre>${escapeHtml(result.content)}</pre>`;
                        }
                        if (result.truncated) {
                            textContent.innerHTML += '<p style="text-align: center; color: var(--text-secondary); margin-top: 1rem;">File truncated to 1MB for preview</p>';
                        }
                    }
                    if(textModal) textModal.classList.add('active');
                } else {
                    alert('Failed to preview text file: ' + (result.error || 'Unknown error') + '.\nAttempting to download instead.');
                    window.location.href = `?download=${encodeURIComponent(rawFileName)}`;
                }
            } catch (error) {
                console.error('Error previewing text file:', error);
                alert('Failed to load text preview. Attempting to download instead.');
                window.location.href = `?download=${encodeURIComponent(rawFileName)}`;
            }
        }
        
        function closeTextViewer() {
            const textModal = document.getElementById('textModal');
            const textContent = document.getElementById('textContent');
            if(textModal) textModal.classList.remove('active');
            if(textContent) textContent.innerHTML = '';
            currentPreviewFile = null;
        }
        
        function openVideoPlayer(videoSrcUrl, rawFileName) {
            currentPreviewFile = rawFileName;
            const video = document.getElementById('videoPlayer');
            const videoTitle = document.getElementById('videoTitle');
            const videoModal = document.getElementById('videoModal');
            if(video) video.src = videoSrcUrl;
            if(videoTitle) videoTitle.textContent = rawFileName;
            if(videoModal) videoModal.classList.add('active');
            if(video) video.play().catch(e => console.warn("Video autoplay prevented:", e));
        }
        
        function closeVideoPlayer(event, isBackdropClick = false) {
            const videoModal = document.getElementById('videoModal');
            // Close if backdrop was clicked OR if it's not a backdrop click (meaning button was clicked)
            if ((isBackdropClick && event && event.target.id === 'videoModal') || !isBackdropClick) {
                if(videoModal) videoModal.classList.remove('active');
                const video = document.getElementById('videoPlayer');
                if(video) {
                    video.pause();
                    video.src = ''; // Release resource
                }
                currentPreviewFile = null;
            }
             if (event && !isBackdropClick) event.stopPropagation();
        }
        
        function openAudioPlayer(audioSrcUrl, rawFileName) {
            currentPreviewFile = rawFileName;
            const audio = document.getElementById('audioPlayer');
            const audioTitle = document.getElementById('audioTitle');
            const audioModal = document.getElementById('audioModal');
            if(audio) audio.src = audioSrcUrl;
            if(audioTitle) audioTitle.textContent = rawFileName;
            if(audioModal) audioModal.classList.add('active');
            if(audio) audio.play().catch(e => console.warn("Audio autoplay prevented:", e));
        }
        
        function closeAudioPlayer() {
            const audioModal = document.getElementById('audioModal');
            const audio = document.getElementById('audioPlayer');
            if(audioModal) audioModal.classList.remove('active');
            if(audio) {
                audio.pause();
                audio.src = ''; // Release resource
            }
            currentPreviewFile = null;
        }
        
        async function openZipViewer(rawFileName) { // Filename is the primary identifier
            currentPreviewFile = rawFileName;
            const formData = new FormData();
            formData.append('action', 'zip_contents');
            formData.append('csrf_token', csrfToken);
            formData.append('filename', rawFileName); // Send raw filename
            
            const zipTitle = document.getElementById('zipTitle');
            const zipInfo = document.getElementById('zipInfo');
            const contentsList = document.getElementById('zipContents');
            const zipModal = document.getElementById('zipModal');

            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                if (result.success) {
                    if(zipTitle) zipTitle.textContent = rawFileName;
                    if(zipInfo) zipInfo.textContent = 
                        `${result.totalFiles} files • ${formatFileSize(result.totalUncompressed)} uncompressed`;
                    
                    if (contentsList) {
                        contentsList.innerHTML = result.contents.map(file => `
                            <li class="zip-file-item">
                                <span class="zip-file-name">${escapeHtml(file.name)}</span>
                                <span class="zip-file-size">${formatFileSize(file.size)}</span>
                            </li>
                        `).join('');
                        
                        if (result.truncated) {
                            contentsList.innerHTML += '<li class="zip-file-item" style="text-align: center; color: var(--text-secondary);">... and more files (preview limited)</li>';
                        }
                    }
                    if(zipModal) zipModal.classList.add('active');
                } else {
                    alert('Failed to preview ZIP: ' + (result.error || 'Unknown error') + '.\nAttempting to download instead.');
                    window.location.href = `?download=${encodeURIComponent(rawFileName)}`;
                }
            } catch (error) {
                console.error('Error previewing ZIP:', error);
                alert('Failed to load ZIP preview. Attempting to download instead.');
                window.location.href = `?download=${encodeURIComponent(rawFileName)}`;
            }
        }
        
        function closeZipViewer() {
            const zipModal = document.getElementById('zipModal');
            const contentsList = document.getElementById('zipContents');
            if(zipModal) zipModal.classList.remove('active');
            if(contentsList) contentsList.innerHTML = '';
            currentPreviewFile = null;
        }
        
        function downloadCurrentFile() {
            if (currentPreviewFile) {
                window.location.href = `?download=${encodeURIComponent(currentPreviewFile)}`;
            }
        }
        
        // Simple markdown renderer (very basic)
        function renderMarkdown(text) {
            if (typeof text !== 'string') return '';
            let html = text;
            // Headers (simplified)
            html = html.replace(/^###### (.*$)/gim, '<h6>$1</h6>');
            html = html.replace(/^##### (.*$)/gim, '<h5>$1</h5>');
            html = html.replace(/^#### (.*$)/gim, '<h4>$1</h4>');
            html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
            html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
            html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');
            // Bold
            html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/__([^_]+)__/g, '<strong>$1</strong>');
            // Italic
            html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>').replace(/_([^_]+)_/g, '<em>$1</em>');
            // Strikethrough
            html = html.replace(/~~(.*?)~~/g, '<del>$1</del>');
            // Links
            html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
            // Code blocks (simple, no syntax highlighting)
            html = html.replace(/```([\s\S]*?)```/g, (match, p1) => `<pre><code>${escapeHtml(p1.trim())}</code></pre>`);
            // Inline code
            html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
            // Blockquotes
            html = html.replace(/^> (.*$)/gim, '<blockquote>$1</blockquote>');
            // Horizontal Rule
            html = html.replace(/^\s*([-*_]){3,}\s*$/gm, '<hr>');
            // Unordered lists
            html = html.replace(/^\s*[\*\-\+] (.*)/gm, '<ul><li>$1</li></ul>');
            html = html.replace(/<\/ul>\s*<ul>/gm, ''); // Merge adjacent lists
            // Ordered lists
            html = html.replace(/^\s*\d+\. (.*)/gm, '<ol><li>$1</li></ol>');
            html = html.replace(/<\/ol>\s*<ol>/gm, ''); // Merge adjacent lists
            // Line breaks (convert newlines to <br>, but not inside pre/code)
            // This is tricky with regex alone. For proper MD, newlines usually don't mean <br> unless two newlines.
            // For a simple preview, we can do this:
            html = html.split('\n').map(line => {
                if (line.trim() === '') return '<br>'; // Keep double newlines as paragraph breaks (effectively)
                return line;
            }).join('<br>').replace(/<br>\s*<br>/g, '<p></p>'); // approximate paragraphs

            // A more robust approach would involve splitting by \n\n for paragraphs first.
            // For now, this is a very basic conversion.
            return html;
        }
        
        // Helper functions
        function escapeHtml(str) {
            if (typeof str !== 'string') return '';
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }
        
        function escapeJs(str) {
            if (typeof str !== 'string') return '';
            return str.replace(/[\\'"]/g, '\\$&').replace(/\n/g, '\\n').replace(/\r/g, '\\r');
        }
        
        function getFileIcon(filename, ext) {
            if (ext === 'folder') return '📁'; // Prioritize folder icon

            if (!ext && filename) { // If ext is not provided but filename is, try to derive ext
                const parts = filename.split('.');
                if (parts.length > 1) {
                    ext = parts.pop().toLowerCase();
                } else {
                    ext = ''; // No extension
                }
            } else if (!ext) {
                ext = ''; // Ensure ext is a string if both are null/undefined
            }
            
            const icons = {
                // Documents
                pdf: '📄', doc: '📝', docx: '📝', txt: '📃', md: '📑', rtf: '📋',
                // Spreadsheets
                xls: '📊', xlsx: '📊', csv: '📈',
                // Archives
                zip: '🗜️', rar: '🗜️', '7z': '🗜️', tar: '🗜️', gz: '🗜️', bz2: '🗜️',
                // Media
                mp3: '🎵', wav: '🎵', ogg: '🎵', m4a: '🎵', flac: '🎵',
                mp4: '🎬', avi: '🎬', mov: '🎬', webm: '🎬', mkv: '🎬', wmv: '🎬',
                // Images
                jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️', svg: '🖼️', webp: '🖼️', bmp: '🖼️', ico: '🖼️',
                // Code/Text
                json: '{}', xml: '</>', html: '🌐', css: '🎨', js: '📜', log: '📋', sh: '', py: '🐍', php: '🐘',
                // Generic
                default: '📎'
            };
            
            return icons[ext] || icons['default'];
        }
        
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function formatDate(timestamp) {
            if (!timestamp) return 'N/A';
            const date = new Date(timestamp * 1000);
            return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) + ' ' + date.toLocaleTimeString();
        }
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                // Close any open preview
                if (document.getElementById('lightbox')?.classList.contains('active')) closeLightbox();
                else if (document.getElementById('pdfModal')?.classList.contains('active')) closePdfViewer();
                else if (document.getElementById('textModal')?.classList.contains('active')) closeTextViewer();
                else if (document.getElementById('videoModal')?.classList.contains('active')) closeVideoPlayer(null, false); // Pass false for non-backdrop
                else if (document.getElementById('audioModal')?.classList.contains('active')) closeAudioPlayer();
                else if (document.getElementById('zipModal')?.classList.contains('active')) closeZipViewer();
            }
        });
        
        // New function to toggle allowed types info
        function toggleAllowedTypesInfo() {
            const allowedTypesDiv = document.getElementById('allowedTypesInfo');
            if (allowedTypesDiv) {
                if (allowedTypesDiv.style.display === 'none' || allowedTypesDiv.style.display === '') {
                    allowedTypesDiv.style.display = 'block';
                } else {
                    allowedTypesDiv.style.display = 'none';
                }
            }
        }

        // *** NEW FUNCTION: updateStorageUsageDisplay ***
        async function updateStorageUsageDisplay() {
            const formData = new FormData();
            formData.append('action', 'get_storage_usage');
            formData.append('csrf_token', csrfToken);

            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const result = await response.json();
                if (result.success) {
                    const usageFill = document.getElementById('storageUsageFill');
                    const usageText = document.getElementById('storageUsageText');
                    const storageProgressContainer = document.querySelector('.storage-progress-container');

                    if (usageFill && usageText && storageProgressContainer) {
                        usageFill.style.width = result.percentageUsed + '%';
                        usageText.textContent = `${formatFileSize(result.currentSize)} / ${formatFileSize(result.maxSize)} (${result.percentageUsed}%)`;
                        storageProgressContainer.style.display = 'block'; // Show the container
                    } else {
                        console.error('Storage usage display elements not found.');
                    }
                } else {
                    console.error('Failed to get storage usage:', result.error);
                     const storageProgressContainer = document.querySelector('.storage-progress-container');
                     if(storageProgressContainer) storageProgressContainer.style.display = 'none'; // Hide if error
                }
            } catch (error) {
                console.error('Error fetching storage usage:', error);
                const storageProgressContainer = document.querySelector('.storage-progress-container');
                if(storageProgressContainer) storageProgressContainer.style.display = 'none'; // Hide if error
            }
        }

        // *** NEW FUNCTIONS FOR MULTI-SELECT ***

        function toggleSelectAll(checked) {
            const checkboxes = document.querySelectorAll('.file-checkbox');
            selectedFiles = []; // Clear current selection
            checkboxes.forEach(checkbox => {
                checkbox.checked = checked;
                const fileItem = checkbox.closest('.file-item, .file-card');
                if (checked) {
                    selectedFiles.push(checkbox.value);
                    fileItem?.classList.add('selected');
                } else {
                    fileItem?.classList.remove('selected');
                }
            });
            updateActionButtons();
        }

        function handleFileSelectionChange() {
            selectedFiles = [];
            const checkboxes = document.querySelectorAll('.file-checkbox');
            let allChecked = true;
            let hasSelection = false;
            checkboxes.forEach(checkbox => {
                const fileItem = checkbox.closest('.file-item, .file-card');
                if (checkbox.checked) {
                    selectedFiles.push(checkbox.value);
                    fileItem?.classList.add('selected');
                    hasSelection = true;
                } else {
                    fileItem?.classList.remove('selected');
                    allChecked = false;
                }
            });
            document.getElementById('selectAllCheckbox').checked = allChecked && checkboxes.length > 0;
            updateActionButtons();
        }

        function updateFileCheckboxesState() {
            const checkboxes = document.querySelectorAll('.file-checkbox');
            let allChecked = true;
            let hasSelection = false;
            if (checkboxes.length === 0) allChecked = false; // No files, so not all checked

            checkboxes.forEach(checkbox => {
                const fileItem = checkbox.closest('.file-item, .file-card');
                if (selectedFiles.includes(checkbox.value)) {
                    checkbox.checked = true;
                    fileItem?.classList.add('selected');
                    hasSelection = true;
                } else {
                    checkbox.checked = false;
                    fileItem?.classList.remove('selected');
                    allChecked = false;
                }
            });
             document.getElementById('selectAllCheckbox').checked = allChecked && checkboxes.length > 0;
        }

        function updateActionButtons() {
            const deleteBtn = document.getElementById('deleteSelectedBtn');
            const downloadBtn = document.getElementById('downloadSelectedBtn');
            const selectAllCheckbox = document.getElementById('selectAllCheckbox');

            if (isSelectionModeActive && selectedFiles.length > 0) {
                if (allowFileDeletion && deleteBtn) { // Check if deleteBtn exists
                    deleteBtn.style.display = 'inline-block';
                }
                downloadBtn.style.display = 'inline-block';
            } else {
                if (deleteBtn) { // Check if deleteBtn exists
                    deleteBtn.style.display = 'none';
                }
                downloadBtn.style.display = 'none';
            }
            // Ensure the main selectAllCheckbox reflects the state if selection mode is off
            if (selectAllCheckbox && !isSelectionModeActive) {
                selectAllCheckbox.checked = false;
            }
        }

        async function deleteSelectedFiles() {
            if (selectedFiles.length === 0) {
                alert('No files selected for deletion.');
                return;
            }
            if (!confirm(`Are you sure you want to delete ${selectedFiles.length} selected file(s)?`)) return;

            let allSucceeded = true;
            for (const filename of selectedFiles) {
                const formData = new FormData();
                formData.append('action', 'delete');
                formData.append('csrf_token', csrfToken);
                formData.append('filename', filename);
                
                try {
                    const response = await fetch('', {
                        method: 'POST',
                        body: formData
                    });
                    const result = await response.json();
                    if (!result.success) {
                        allSucceeded = false;
                        console.error(`Failed to delete ${filename}: ${result.error}`);
                    }
                } catch (error) {
                    allSucceeded = false;
                    console.error(`Error deleting ${filename}:`, error);
                }
            }

            selectedFiles = []; 
            loadFiles(); 
            updateStorageUsageDisplay(); // Update storage after deletion
            // updateActionButtons() will be called by loadFiles -> displayFiles
            // document.getElementById('selectAllCheckbox').checked = false; // Handled by updateActionButtons now

            if (!allSucceeded) {
                alert('Some files could not be deleted. Check console for details.');
            }
        }

        function downloadSelectedFiles() {
            if (selectedFiles.length === 0) {
                alert('No files selected for download.');
                return;
            }
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = ''; 

            const actionInput = document.createElement('input');
            actionInput.type = 'hidden';
            actionInput.name = 'action';
            actionInput.value = 'download_selected_zip';
            form.appendChild(actionInput);

            const csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = 'csrf_token';
            csrfInput.value = csrfToken; // Already defined globally
            form.appendChild(csrfInput);

            selectedFiles.forEach(filename => {
                const fileInput = document.createElement('input');
                fileInput.type = 'hidden';
                fileInput.name = 'filenames[]';
                fileInput.value = filename;
                form.appendChild(fileInput);
            });

            document.body.appendChild(form);
            form.submit();
            document.body.removeChild(form);
        }

        // *** END NEW FUNCTIONS FOR MULTI-SELECT ***

        function isMobileView() {
            return window.innerWidth < 768; // Consistent with CSS media queries
        }

        function toggleSelectionMode() {
            isSelectionModeActive = !isSelectionModeActive;
            const container = document.querySelector('.container');
            const toggleBtn = document.getElementById('toggleSelectionModeBtn');
            const selectAllContainer = document.getElementById('selectAllContainer');

            if (isSelectionModeActive) {
                container.classList.add('selection-active');
                toggleBtn.textContent = 'Cancel Selection'; // Text for screen readers/title
                toggleBtn.innerHTML = '❌'; // Icon
                toggleBtn.title = 'Cancel Selection';
                selectAllContainer.style.display = 'flex';
            } else {
                container.classList.remove('selection-active');
                toggleBtn.textContent = 'Select'; // Text for screen readers/title
                toggleBtn.innerHTML = '☐'; // Icon
                toggleBtn.title = 'Select';
                selectAllContainer.style.display = 'none';
                
                // Clear selection when exiting mode
                selectedFiles = [];
                document.querySelectorAll('.file-checkbox').forEach(cb => {
                    cb.checked = false;
                    // Also remove visual indication from parent file item/card
                    const fileItem = cb.closest('.file-item, .file-card');
                    fileItem?.classList.remove('selected');
                });
                const selectAllGlobalCheckbox = document.getElementById('selectAllCheckbox');
                if(selectAllGlobalCheckbox) selectAllGlobalCheckbox.checked = false;
            }
            updateActionButtons();
        }

        // Logout Function
        async function handleLogout() {
            const formData = new FormData();
            formData.append('action', 'logout');
            formData.append('csrf_token', csrfToken); // Ensure csrfToken is globally available

            try {
                const response = await fetch('', { // Assuming current page handles actions
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                if (result.success) {
                    window.location.reload();
                } else {
                    alert('Logout failed. Please try again.');
                }
            } catch (error) {
                console.error('Logout error:', error);
                alert('An error occurred during logout.');
            }
        }

        function navigateToDirectory(path) {
            currentDirectoryPath = path;
            loadFiles(); // Will use the updated currentDirectoryPath
        }

        async function handleCreateFolderClick() {
            const folderName = window.prompt("Enter name for the new folder:");
            if (folderName === null || folderName.trim() === "") {
                if (folderName !== null) { // Only alert if they entered empty string, not if they cancelled
                    alert("Folder name cannot be empty.");
                }
                return;
            }

            // Basic client-side validation for invalid characters (server will do more)
            if (/[/\\:\*\?"<>\|\.]/.test(folderName) || folderName === ".." || folderName === ".") {
                alert("Folder name contains invalid characters or is not allowed.");
                return;
            }

            const formData = new FormData();
            formData.append('action', 'create_folder');
            formData.append('csrf_token', csrfToken);
            formData.append('folderName', folderName.trim());
            formData.append('currentPath', currentDirectoryPath);

            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                if (result.success) {
                    loadFiles(); // Refresh the current directory to show the new folder
                } else {
                    alert('Failed to create folder: ' + (result.error || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error creating folder:', error);
                alert('An error occurred while creating the folder.');
            }
        }

        // *** NEW FUNCTION: handleRenameClick ***
        async function handleRenameClick(itemIdentifier, currentName) {
            event.stopPropagation(); // Prevent triggering click on parent elements
            const newName = prompt(`Enter new name for "${currentName}":`, currentName);

            if (newName === null || newName.trim() === "") {
                if (newName !== null) alert("New name cannot be empty.");
                return;
            }

            if (newName === currentName) {
                // No change, do nothing
                return;
            }

            // Basic client-side validation for invalid characters (server will do more)
            if (/[/\\:\*\?"<>\|]/.test(newName)) {
                alert("New name contains invalid characters.");
                return;
            }

            const formData = new FormData();
            formData.append('action', 'rename');
            formData.append('csrf_token', csrfToken);
            formData.append('itemIdentifier', itemIdentifier); // This is the full path relative to FILES_DIR
            formData.append('newName', newName.trim());

            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                if (result.success) {
                    loadFiles(); // Refresh file list
                    // Consider updating currentDirectoryPath if a folder in the breadcrumb path was renamed
                    // This might require more sophisticated state management or specific feedback from the server.
                    // For now, a simple loadFiles() will refresh the current view.
                    if (currentDirectoryPath.startsWith(itemIdentifier + '/')) {
                        // If we are inside a folder that got renamed, its path might need an update
                        // This is a tricky case. For now, a full refresh might be the simplest.
                        // Or, the server could return the new path of the renamed item if it was a dir.
                    }
                } else {
                    alert('Rename failed: ' + (result.error || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error renaming item:', error);
                alert('An error occurred while renaming the item.');
            }
        }
    </script>
</body>
</html>