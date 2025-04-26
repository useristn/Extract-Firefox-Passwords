<?php
// Hàm kiểm tra định dạng tên miền hoặc IP
function isValidTarget($target) {
    // Chỉ cho phép tên miền (ví dụ: example.com) hoặc địa chỉ IPv4/IPv6
    $domainPattern = '/^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$/';
    $ipv4Pattern = '/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/';
    $ipv6Pattern = '/^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$/';
    
    return preg_match($domainPattern, $target) || preg_match($ipv4Pattern, $target) || preg_match($ipv6Pattern, $target);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['command'], $_POST['target'])) {
    $cmd = $_POST['command'];
    $target = trim($_POST['target']);

    // Kiểm tra độ dài target (tránh input quá dài)
    if (strlen($target) > 255 || strlen($target) === 0) {
        http_response_code(400);
        echo htmlspecialchars("❌ Invalid target length.");
        exit;
    }

    // Kiểm tra định dạng target
    if (!isValidTarget($target)) {
        http_response_code(400);
        echo htmlspecialchars("❌ Invalid target format. Only domain names or IP addresses are allowed.");
        exit;
    }

    // Chỉ cho phép các lệnh hợp lệ
    $allowedCommands = ['ping', 'nslookup', 'dig'];
    if (!in_array($cmd, $allowedCommands, true)) {
        http_response_code(400);
        echo htmlspecialchars("❌ Invalid command.");
        exit;
    }

    // Thoát ký tự đặc biệt cho target
    $target = escapeshellarg($target);

    // Thực thi lệnh với timeout và giới hạn
    $output = '';
    switch ($cmd) {
        case 'ping':
            $output = shell_exec("timeout 5 ping -c 5 $target 2>&1");
            break;
        case 'nslookup':
            $output = shell_exec("timeout 5 nslookup $target 2>&1");
            break;
        case 'dig':
            $output = shell_exec("timeout 5 dig $target 2>&1");
            break;
    }

    // Kiểm tra nếu lệnh thất bại hoặc không có output
    if ($output === null) {
        http_response_code(500);
        echo htmlspecialchars("❌ Command execution failed.");
        exit;
    }

    // Giới hạn kích thước output (ví dụ: 10KB)
    if (strlen($output) > 10240) {
        http_response_code(400);
        echo htmlspecialchars("❌ Output too large.");
        exit;
    }

    // Xuất output an toàn với HTML encoding
    header('Content-Type: text/plain');
    echo htmlspecialchars($output, ENT_QUOTES, 'UTF-8');
    exit;
}

// Nếu không phải POST hoặc thiếu tham số
http_response_code(400);
echo htmlspecialchars("❌ Invalid request.");
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>🌐 Network Tools</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        body {
            background-color: #121212;
            color: #f1f1f1;
            font-family: 'Fira Code', monospace;
            padding-top: 50px;
        }
        .tool-card {
            background-color: #1f1f1f;
            border: 1px solid #333;
            border-radius: 16px;
            padding: 2rem;
            box-shadow: 0 0 10px rgba(0,0,0,0.5);
        }
        select, input, button {
            font-family: inherit;
        }
        select, input {
            background-color: #2a2a2a;
            color: #f1f1f1;
            border: 1px solid #444;
        }
        select:focus, input:focus {
            outline: none;
            border-color: #66ff66;
            box-shadow: 0 0 5px #66ff66;
        }
        .btn-primary {
            background-color: #66ff66;
            border: none;
            color: #000;
        }
        .btn-primary:hover {
            background-color: #55dd55;
        }
        pre {
            background-color: #202020;
            color: #00ff00;
            padding: 1rem;
            border-radius: 10px;
            margin-top: 1rem;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        #spinner {
            display: none;
            width: 20px;
            margin-left: 10px;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="tool-card mx-auto" style="max-width: 700px;">
        <h1 class="text-center mb-4"><i class="bi bi-hdd-network"></i> Network Diagnostic</h1>
        <form id="tool-form">
            <div class="row mb-3">
                <div class="col-md-4">
                    <select name="command" class="form-select">
                        <option value="ping">Ping</option>
                        <option value="nslookup">NSLookup</option>
                        <option value="dig">Dig</option>
                    </select>
                </div>
                <div class="col-md-8">
                    <input type="text" name="target" class="form-control" placeholder="Enter a domain or IP..." required>
                </div>
            </div>
            <button type="submit" class="btn btn-primary w-100">
                <i class="bi bi-play-fill"></i> Run
                <img id="spinner" src="https://i.imgur.com/llF5iyg.gif" alt="Loading...">
            </button>
        </form>
        <pre id="output" class="mt-4">💡 Output will appear here...</pre>
        <div id="log" class="mt-2 text-success" style="font-size: 0.9rem;"></div>
    </div>
</div>

<script>
    const form = document.getElementById('tool-form');
    const output = document.getElementById('output');
    const spinner = document.getElementById('spinner');
    const log = document.getElementById('log');

    form.addEventListener('submit', function(e) {
        e.preventDefault();
        output.textContent = "⏳ Running command...";
        spinner.style.display = "inline-block";

        const formData = new FormData(form);
        const command = formData.get("command");
        const target = formData.get("target");
        log.textContent = `🟢 ${command} ${target}`;

        fetch("", {
            method: "POST",
            body: formData
        })
        .then(res => res.text())
        .then(data => {
            spinner.style.display = "none";
            output.textContent = "⏳ Running command...\n\n";
            let i = 0;
            const interval = setInterval(() => {
                if (i < data.length) {
                    output.textContent += data[i++];
                } else {
                    clearInterval(interval);
                }
            }, 5);
        })
        .catch(err => {
            spinner.style.display = "none";
            output.textContent = "❌ Error occurred: " + err.message;
        });
    });
</script>
</body>
</html>