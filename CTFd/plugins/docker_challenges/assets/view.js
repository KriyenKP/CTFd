CTFd._internal.challenge.data = undefined

CTFd._internal.challenge.renderer = CTFd._internal.markdown;


CTFd._internal.challenge.preRender = function () { }

CTFd._internal.challenge.render = function (markdown) {

    return CTFd._internal.challenge.renderer.parse(markdown)
}


CTFd._internal.challenge.postRender = function () {
    const containername = CTFd._internal.challenge.data.docker_image;
    get_docker_status(containername);
    createWarningModalBody();
}

function createWarningModalBody() {
    // Creates the Warning Modal placeholder, that will be updated when stuff happens.
    if (CTFd.lib.$('#warningModalBody').length === 0) {
        CTFd.lib.$('body').append('<div id="warningModalBody"></div>');
    }
}

function get_docker_status(container) {
    // Use CTFd.fetch to call the API
    CTFd.fetch("/api/v1/docker_status").then(response => response.json())
        .then(result => {
            result.data.forEach(item => {
                if (item.docker_image == container) {
                    // Split the ports and create the data string
                    var ports = String(item.ports).split(',');
                    var data = '';

                    ports.forEach(port => {
                        port = String(port);
                        data = data + 'Host: ' + item.host + '<br />Port: ' + port + '<br /><br />';
                    });
                    // Create connection instructions based on configured connection type or auto-detect
                    var connectionInstructions = '';
                    var firstPort = ports[0].split("/")[0];
                    var containerLower = container.toLowerCase();

                    // Get the configured connection type from challenge data
                    var connectionType = CTFd._internal.challenge.data.connection_type || 'auto';

                    // Auto-detect service type if connection_type is 'auto'
                    if (connectionType === 'auto') {
                        var isHttpPort = ['80', '8080', '3000', '5000', '8000', '8888', '9000', '4000', '8081'].includes(firstPort);
                        var isWebService = containerLower.includes('web') || containerLower.includes('http') || containerLower.includes('nginx') || containerLower.includes('apache');
                        var isSshService = firstPort === '22' || containerLower.includes('ssh');
                        var isFtpService = firstPort === '21' || containerLower.includes('ftp');

                        if (isHttpPort || isWebService) {
                            connectionType = 'http';
                        } else if (isSshService) {
                            connectionType = 'ssh';
                        } else if (isFtpService) {
                            connectionType = 'ftp';
                        } else {
                            connectionType = 'netcat';
                        }
                    }

                    // Use direct IP connection to avoid SSL certificate complexity
                    // Generate instructions based on connection type
                    if (connectionType === 'http') {
                        var httpUrl = 'http://' + item.host + ':' + firstPort;

                        connectionInstructions = '<div class="alert alert-info mt-2">' +
                            '<strong>🌐 Web Application:</strong><br><br>' +
                            'URL: <code class="bg-dark text-info px-2 py-1 rounded">' + httpUrl + '</code><br><br>' +
                            '<a href="' + httpUrl + '" target="_blank" class="btn btn-sm btn-outline-light">' +
                            '<i class="fas fa-external-link-alt"></i> Open in Browser</a>' +
                            '<br><small class="text-muted mt-2">Note: Challenge services use HTTP (not HTTPS) for direct access</small>' +
                            '</div>';
                    } else if (connectionType === 'ssh') {
                        connectionInstructions = '<div class="alert alert-success mt-2">' +
                            '<strong>🔐 SSH Service:</strong><br><br>' +
                            'Host: <code class="bg-dark text-success px-2 py-1 rounded">' + item.host + '</code><br>' +
                            'Port: <code class="bg-dark text-success px-2 py-1 rounded">' + firstPort + '</code><br><br>' +
                            'Command: <code class="bg-dark text-success px-2 py-1 rounded">ssh user@' + item.host + ' -p ' + firstPort + '</code><br>' +
                            '<small class="text-muted">Replace "user" with the appropriate username (often: root, admin, ctf, or challenge-specific)</small>' +
                            '</div>';
                    } else if (connectionType === 'ftp') {
                        connectionInstructions = '<div class="alert alert-primary mt-2">' +
                            '<strong>📁 FTP Service:</strong><br><br>' +
                            'Host: <code class="bg-dark text-primary px-2 py-1 rounded">' + item.host + '</code><br>' +
                            'Port: <code class="bg-dark text-primary px-2 py-1 rounded">' + firstPort + '</code><br><br>' +
                            'FTP: <code class="bg-dark text-primary px-2 py-1 rounded">ftp ' + item.host + ' ' + firstPort + '</code><br>' +
                            'Netcat: <code class="bg-dark text-info px-2 py-1 rounded">nc ' + item.host + ' ' + firstPort + '</code>' +
                            '</div>';
                    } else { // netcat or any other type
                        var serviceIcon = containerLower.includes('netcat') || containerLower.includes('nc') ? '🔌' : '🔗';
                        var serviceType = containerLower.includes('netcat') || containerLower.includes('nc') ? 'Netcat Service' : 'Network Service';

                        connectionInstructions = '<div class="alert alert-warning mt-2">' +
                            '<strong>' + serviceIcon + ' ' + serviceType + ':</strong><br><br>' +
                            'Host: <code class="bg-dark text-warning px-2 py-1 rounded">' + item.host + '</code><br>' +
                            'Port: <code class="bg-dark text-warning px-2 py-1 rounded">' + firstPort + '</code><br><br>' +
                            'Netcat: <code class="bg-dark text-warning px-2 py-1 rounded">nc ' + item.host + ' ' + firstPort + '</code><br>' +
                            'Telnet: <code class="bg-dark text-info px-2 py-1 rounded">telnet ' + item.host + ' ' + firstPort + '</code>' +
                            '</div>';
                    }

                    // Update the DOM with the docker container information
                    CTFd.lib.$('#docker_container').html('<div class="card bg-dark text-light border-secondary"><div class="card-body"><h6 class="card-title text-info">Docker Container Information:</h6><pre class="text-light bg-dark border-0 mb-0">' + data + '</pre>' +
                        connectionInstructions +
                        '<div class="mt-2" id="' + String(item.instance_id).substring(0, 10) + '_revert_container"></div></div></div>');

                    // Update the DOM with connection info information.
                    // Note that connection info should contain "host" and "port"
                    var $link = CTFd.lib.$('.challenge-connection-info');
                    $link.html($link.html().replace(/host/gi, item.host));
                    $link.html($link.html().replace(/port|\b\d{5}\b/gi, ports[0].split("/")[0]));

                    // Enhanced connection info processing
                    CTFd.lib.$(".challenge-connection-info").each(function () {
                        const $span = CTFd.lib.$(this);
                        let html = $span.html();

                        // Skip if already has a link
                        if (html.includes("<a")) {
                            return;
                        }

                        // If it contains "http", try to extract and wrap it
                        const urlMatch = html.match(/(http[s]?:\/\/[^\s<]+)/);

                        if (urlMatch) {
                            const url = urlMatch[0];
                            const linked = html.replace(url, `<a href="${url}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-primary ms-1"><i class="fas fa-external-link-alt"></i> ${url}</a>`);
                            $span.html(linked);
                        } else {
                            // If no HTTP but looks like it might be a connection string, add netcat instructions
                            if (html.toLowerCase().includes('nc ') || html.toLowerCase().includes('netcat') || html.toLowerCase().includes('connect')) {
                                // Already has connection instructions, leave as is
                            } else if (html.includes(':') && /\d+/.test(html)) {
                                // Looks like it might be host:port format, add helpful note
                                $span.html(html + '<br><small class="text-muted"><i class="fas fa-info-circle"></i> Use netcat to connect: <code>nc [host] [port]</code></small>');
                            }
                        }
                    });

                    // Set up the countdown timer
                    var countDownDate = new Date(parseInt(item.revert_time) * 1000).getTime();
                    var x = setInterval(function () {
                        var now = new Date().getTime();
                        var distance = countDownDate - now;
                        var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                        var seconds = Math.floor((distance % (1000 * 60)) / 1000);
                        if (seconds < 10) {
                            seconds = "0" + seconds;
                        }

                        // Update the countdown display
                        CTFd.lib.$("#" + String(item.instance_id).substring(0, 10) + "_revert_container").html('<small class="text-warning">Stop or Revert Available in ' + minutes + ':' + seconds + '</small>');

                        // Check if the countdown is finished and enable the revert button
                        if (distance < 0) {
                            clearInterval(x);
                            CTFd.lib.$("#" + String(item.instance_id).substring(0, 10) + "_revert_container").html(
                                '<a onclick="start_container(\'' + item.docker_image + '\');" class="btn btn-warning btn-sm me-2">' +
                                '<i class="fas fa-redo"></i> Revert</a> ' +
                                '<a onclick="stop_container(\'' + item.docker_image + '\');" class="btn btn-danger btn-sm">' +
                                '<i class="fas fa-stop"></i> Stop</a>'
                            );
                        }
                    }, 1000);

                    return false; // Stop once the correct container is found
                }
            });
        })
        .catch(error => {
            console.error('Error fetching docker status:', error);
        });
    // Display the normal start button, if there is no need for updating
    const NormalStartButtonHTML = `
        <div class="text-center">
            <a onclick="start_container('${CTFd._internal.challenge.data.docker_image}');" class='btn btn-success btn-lg'>
                <i class="fas fa-play"></i> Start Docker Instance
            </a>
        </div>`
    CTFd.lib.$('#docker_container').html(NormalStartButtonHTML);
}

function stop_container(container) {
    if (confirm("Are you sure you want to stop the container for: \n" + CTFd._internal.challenge.data.name)) {
        CTFd.fetch("/api/v1/container?name=" + encodeURIComponent(container) +
            "&challenge=" + encodeURIComponent(CTFd._internal.challenge.data.name) +
            "&stopcontainer=True", {
            method: "GET"
        })
            .then(function (response) {
                return response.json().then(function (json) {
                    if (response.ok) {
                        updateWarningModal({
                            title: "Attention!",
                            warningText: "The Docker container for <br><strong>" + CTFd._internal.challenge.data.name + "</strong><br> was stopped successfully.",
                            buttonText: "Close",
                            onClose: function () {
                                get_docker_status(container);  // ← Will be called when modal is closed
                            }
                        });
                    } else {
                        throw new Error(json.message || 'Failed to stop container');
                    }
                });
            })
            .catch(function (error) {
                updateWarningModal({
                    title: "Error",
                    warningText: error.message || "An unknown error occurred while stopping the container.",
                    buttonText: "Close",
                    onClose: function () {
                        get_docker_status(container);  // ← Will be called when modal is closed
                    }
                });

            });
    }
}

function start_container(container) {
    CTFd.lib.$('#docker_container').html('<div class="text-center py-3"><i class="fas fa-circle-notch fa-spin fa-2x text-primary"></i><br><small class="text-muted mt-2">Starting container...</small></div>');
    CTFd.fetch("/api/v1/container?name=" + encodeURIComponent(container) + "&challenge=" + encodeURIComponent(CTFd._internal.challenge.data.name), {
        method: "GET"
    }).then(function (response) {
        return response.json().then(function (json) {
            if (response.ok) {
                get_docker_status(container);

                updateWarningModal({
                    title: "Container Started Successfully!",
                    warningText: `🐳 A Docker container has been started for you.<br><br>
                        <strong>Connection Instructions:</strong><br>
                        • <strong>Web services:</strong> Look for clickable HTTP links<br>
                        • <strong>Network services:</strong> Use <code>nc [host] [port]</code> or <code>telnet [host] [port]</code><br>
                        • <strong>SSH services:</strong> Use <code>ssh user@[host] -p [port]</code><br><br>
                        <strong>⚠️ Important:</strong> You can only revert or stop a container once every 5 minutes!<br><br>
                        The container information will appear above once it's fully ready.`,
                    buttonText: "Got it!"
                });

            } else {
                throw new Error(json.message || 'Failed to start container');
            }
        });
    }).catch(function (error) {
        // Handle error and notify the user
        updateWarningModal({
            title: "Error!",
            warningText: error.message || "An unknown error occurred when starting your Docker container.",
            buttonText: "Got it!",
            onClose: function () {
                get_docker_status(container);  // ← Will be called when modal is closed
            }
        });
    });
}

// WE NEED TO CREATE THE MODAL FIRST, and this should be only used to fill it.

function updateWarningModal({
    title, warningText, buttonText, onClose } = {}) {
    const modalHTML = `
        <div id="warningModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; z-index:9999; background-color:rgba(0,0,0,0.7);">
          <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content bg-dark text-light border-secondary">
              <div class="modal-header bg-warning text-dark border-secondary">
                <h5 class="modal-title">${title}</h5>
                <button type="button" id="warningCloseBtn" class="btn-close btn-close-white" aria-label="Close"></button>
              </div>
              <div class="modal-body text-light">
                ${warningText}
              </div>
              <div class="modal-footer border-secondary">
                <button type="button" class="btn btn-primary" id="warningOkBtn">${buttonText}</button>
              </div>
            </div>
          </div>
        </div>
    `;
    CTFd.lib.$("#warningModalBody").html(modalHTML);

    // Show the modal
    CTFd.lib.$("#warningModal").show();

    // Close logic with callback
    const closeModal = () => {
        CTFd.lib.$("#warningModal").hide();
        if (typeof onClose === 'function') {
            onClose();
        }
    };

    CTFd.lib.$("#warningCloseBtn").on("click", closeModal);
    CTFd.lib.$("#warningOkBtn").on("click", closeModal);
}

// In order to capture the flag submission, and remove the "Revert" and "Stop" buttons after solving a challenge
// We need to hook that call, and do this manually.
function checkForCorrectFlag() {
    const challengeWindow = document.querySelector('#challenge-window');
    if (!challengeWindow || getComputedStyle(challengeWindow).display === 'none') {
        // console.log("❌ Challenge window hidden or closed, stopping check.");
        clearInterval(checkInterval);
        checkInterval = null;
        return;
    }

    const notification = document.querySelector('.notification-row .alert');
    if (!notification) return;

    const strong = notification.querySelector('strong');
    if (!strong) return;

    const message = strong.textContent.trim();

    if (message.includes("Correct")) {
        // console.log("✅ Correct flag detected:", message);
        get_docker_status(CTFd._internal.challenge.data.docker_image);
        clearInterval(checkInterval);
        checkInterval = null;
    }
}

if (!checkInterval) {
    var checkInterval = setInterval(checkForCorrectFlag, 1500);
}
