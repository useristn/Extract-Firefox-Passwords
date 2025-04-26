<?php
if (isset($_POST['command'], $_POST['target'])) {
    $cmd = $_POST['command'];
    $target = escapeshellarg($_POST['target']);
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
        default:
            $output = "❌ Invalid command.";
    }
    echo escapeshellarg($output);
    exit;
}
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