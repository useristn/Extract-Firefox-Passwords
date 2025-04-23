<?php
    if(isset($_POST['command'],$_POST['target'])){
        $command = $_POST['command'];
        $target = $_POST['target'];
		switch($command) {
			case "ping":
				$result = shell_exec("timeout 10 ping -c 4 $target 2>&1");
				break;
			case "nslookup":
				$result = shell_exec("timeout 10 nslookup $target 2>&1");
				break;	
            case "dig":
                $result = shell_exec("timeout 10 dig $target 2>&1");
                break;
            case "backup":
				$result = shell_exec("timeout 3 zip /tmp/$target -r /var/www/html/index.php 2>&1");
                if ($result !== null && strpos($result, "zip error") === false)
                    die("Backup thành công");
                else
                    die("Backup không thành công");
				break;
		}
		die($result);
    }
?>
<html>
<head>
    <title>Network Tool</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootswatch/4.5.2/sketchy/bootstrap.min.css" integrity="sha384-RxqHG2ilm4r6aFRpGmBbGTjsqwfqHOKy1ArsMhHusnRO47jcGqpIQqlQK/kmGy9R" crossorigin="anonymous">
    <style>
        body {
            background-color: #f8f9fa;
            font-family: Arial, sans-serif;
        }
        .container {
            margin-top: 50px;
        }
        .page-header {
            text-align: center;
            margin-bottom: 30px;
        }
        h1 {
            font-size: 2.5rem;
            color: #343a40;
        }
        form {
            margin-top: 20px;
        }
        select, input[type="text"] {
            margin-right: 10px;
            padding: 5px;
            font-size: 1rem;
        }
        button {
            font-size: 1rem;
        }
        pre {
            background-color: #e9ecef;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .next-level-btn {
            margin-top: 20px;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="page-header" id="banner">
        <h1>Network Tool</h1>
        <form action="#" id="frm_tool">
            <select name="command" class="form-control d-inline-block" style="width: auto;">
                <option value="backup">Backup</option>
                <option value="nslookup">NSLookup</option>
                <option value="ping">Ping</option>
                <option value="dig">Dig</option>
            </select>
            <input type="text" name="target" class="form-control d-inline-block" style="width: auto;" placeholder="Enter target" />
            <button class="btn btn-primary">Check</button>
        </form>
        <pre id="result"></pre>
        <button class="btn btn-secondary next-level-btn" onclick="nextLevel()">Next Level</button>
    </div>
</div>

<script>
    function nextLevel() {
        const url = new URL(window.location.origin);
        url.port = (parseInt(url.port) + 1).toString();
        window.location.href = url.toString();
    }

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
