$(document).ready(function () {

    $("#wsBtn").on("click", () => {
        const protocolPrefix = (window.location.protocol === 'https:') ? 'wss:' : 'ws:';
        const socket = new WebSocket(protocolPrefix + '//' + location.host + "/websocket");
        socket.onopen = () => {
            socket.send("ping")
        }

        socket.onmessage = (event) => {
            $("#wsResult").val(event.data)
            socket.close()
        }

        socket.onclose = (event) => {
            if (event.wasClean) {
                console.log(`[close] Connection closed cleanly, code=${event.code} reason=${event.reason}`);
            } else {
                console.log('[close] Connection died')
            }
        }
    })

    $("#loadIframeBtn").on("click", () => {
        $("#test-iframe").attr('src', $("#iframeInput").val())
    })

    $("#ajaxIframeBtn").on("click", () => {
        $.getJSON($("#ajaxInput").val(), (data, status, jqXHR) => {

            $("#ajaxResult").val(JSON.stringify(data))
            let body = []
            $("#ajaxHeadersResult").empty()
            jqXHR.getAllResponseHeaders().split("\n").forEach(header => {
                let kv = header.split(":")
                if (kv.length == 2) {
                    body.push('<tr class="row"><td class="col-2">' + kv[0] + '</td><td class="col-10"><small class="text-break text-muted">' + kv[1] + '</small></td></tr>')
                }
            })
            $("#ajaxHeadersResult").append(body)

        });
    })

    $("#jwtBtn").on("click", () => {
        $.getJSON("/jwt", (data) => {

            let command = "curl -H 'Authorization: Bearer " + data.Token + "' " + window.location.protocol + '//' + window.location.host + "/api/post"
            let append = '<small class="text-break text-muted">' + command + '</small>'
            $("#jwtResult").append(append)

        });
    })

});

