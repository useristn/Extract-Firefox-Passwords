<?php
    if (isset($_POST['command'], $_POST['target'])) {
        $command = $_POST['command'];
        // $target = escapeshellarg($_POST['target']); // Escape input to prevent command injection
        $target = $_POST['target'];

        switch ($command) {
            case "ping":
                $result = shell_exec("timeout 10 ping -c 4 $target 2>&1");
                break;
            case "nslookup":
                $result = shell_exec("timeout 10 nslookup $target 2>&1");
                break;
            case "dig":
                $result = shell_exec("timeout 10 dig $target 2>&1");
                break;
            default:
                $result = "Invalid command.";
                break;
        }
        die(htmlspecialchars($result, ENT_QUOTES, 'UTF-8')); // Escape output to prevent XSS
    }
?>
<html>
<head>
    <title>🔥 Network Tool 🔥</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootswatch/4.5.2/cyborg/bootstrap.min.css" integrity="sha384-1CmrxMRARb6aLqgBO7yyAxTOQE2AKb9GfXnEaZxj8z5yj1z5boVx1FAdbrUkg6jF" crossorigin="anonymous">
    <style>
        body {
            background-color: #1a1a1a;
            color: #f8f9fa;
            font-family: 'Courier New', Courier, monospace;
        }
        .container {
            margin-top: 50px;
        }
        .page-header {
            text-align: center;
            margin-bottom: 30px;
        }
        h1 {
            font-size: 3rem;
            color: #ff4500;
            text-shadow: 2px 2px 5px #000;
        }
        form {
            margin-top: 20px;
        }
        select, input[type="text"] {
            margin-right: 10px;
            padding: 10px;
            font-size: 1.2rem;
            border: 2px solid #ff4500;
            background-color: #333;
            color: #f8f9fa;
        }
        button {
            font-size: 1.2rem;
            background-color: #ff4500;
            border: none;
            color: #fff;
            padding: 10px 20px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        button:hover {
            background-color: #e63900;
        }
        pre {
            background-color: #333;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            white-space: pre-wrap;
            word-wrap: break-word;
            color: #00ff00;
            font-size: 1.1rem;
        }
        .next-level-btn {
            margin-top: 20px;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="page-header" id="banner">
        <h1>🔥 Network Tool 🔥</h1>
        <form action="#" id="frm_tool">
            <select name="command" class="form-control d-inline-block" style="width: auto;">
                <option value="ping">Ping</option>
                <option value="nslookup">NSLookup</option>
                <option value="dig">Dig</option>
            </select>
            <input type="text" name="target" class="form-control d-inline-block" style="width: auto;" placeholder="Enter target" />
            <button class="btn btn-primary">🔥 Check 🔥</button>
        </form>
        <pre id="result"></pre>
    </div>
</div>

<script>
    const frm_tool = document.getElementById('frm_tool');
    const result_div = document.getElementById('result');

    frm_tool.addEventListener('submit', function(event) {
        event.preventDefault();
        result_div.innerHTML = `<img src="https://i.imgur.com/llF5iyg.gif" alt="Loading..." style="display: block; margin: 0 auto;" />`;
        fetch('index.php', {
            method: 'POST',
            body: new FormData(frm_tool)
        })
        .then(response => response.text())
        .then(data => {
            result_div.innerText = data;
        })
        .catch(error => {
            result_div.innerText = 'An error occurred: ' + error.message;
        });
    });
</script>
</body>
</html>