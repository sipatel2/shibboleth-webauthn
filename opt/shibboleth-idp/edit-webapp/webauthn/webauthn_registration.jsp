<!DOCTYPE html>

<html>
  <head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta charset="utf-8"/>
    <link rel="icon" type="image/png" href="https://shib.oit.duke.edu/idms-assets/src/img/favicon.ico">
    <script src="https://shib.oit.duke.edu/idms-assets/dist/bundle.js"></script>
    <title>WebAuthn</title>

    <script type="text/javascript" src="/idp/js/jquery-3.3.1.min.js"></script>

    <script src="/idp/webauthn/lib/text-encoding-0.7.0/encoding.js"></script>
    <script src="/idp/webauthn/lib/text-encoding-0.7.0/encoding-indexes.js"></script>
    <script src="/idp/webauthn/lib/fetch/fetch-3.0.0.js"></script>
    <script src="/idp/webauthn/lib/base64js/base64js-1.3.0.min.js"></script>
    <script src="/idp/webauthn/js/base64url.js"></script>
    <script src="/idp/webauthn/js/webauthn.js"></script>

    <script type="application/javascript">
      $(document).ready(function() {
        function rejectIfNotSuccess(response) {
          if (response.success) {
            return response;
          } else {
            return new Promise((resolve, reject) => reject(response));
          }
        }

        function rejected(err) {
          return new Promise((resolve, reject) => reject(err));
        }

        function setStatus(statusText) {
          document.getElementById('status').innerHTML = statusText;
        }

        function getRegisterRequest(username, credentialNickname, requireResidentKey = false) {
          return fetch("/idp/webauthn/registration?type=start", {
            body: new URLSearchParams({
              username,
              credentialNickname,
              requireResidentKey,
            }),
            method: 'POST',
          })
            .then(response => response.json())
            .then(rejectIfNotSuccess)
          ;
        }

        function executeRegisterRequest(request) {
          return webauthn.createCredential(request.publicKeyCredentialCreationOptions);
        }

        function submitResponse(requestId, response) {
          const body = {
            requestId,
            credential: response,
          };

          return fetch("/idp/webauthn/registration?type=finish", {
            method: 'POST',
            body: JSON.stringify(body),
          }).then(response => response.json());
          ;
        }

        function performCeremony(params) {
          const getRequest = params.getRequest; /* function(urls: object): { publicKeyCredentialCreationOptions: object } | { publicKeyCredentialRequestOptions: object } */
          const executeRequest = params.executeRequest; /* function({ publicKeyCredentialCreationOptions: object } | { publicKeyCredentialRequestOptions: object }): Promise[PublicKeyCredential] */
          const handleError = params.handleError; /* function(err): ? */

          return getRequest()
            .then((params) => {
              const request = params.request;
              setStatus('Asking authenticators to create credential..');
              return executeRequest(request)
                .then(webauthn.responseToObject)
                .then(response => ({
                  request,
                  response,
                }));
            })

            .then((params) => {
              const request = params.request;
              const response = params.response;

              setStatus('Sending response to server...');
              return submitResponse(request.requestId, response);
            })

            .then(data => {
              if (data && data.success) {
                setStatus('Registration successful!');
                $('#status').addClass("message success");
                $('#credentialNickname').prop("disabled", true);
              } else {
                setStatus('An error occurred during registration.  Are you using a supported device/browser?');
                $('#submit').show();
                $('#status').addClass("message error");
              }
              return data;
            })
          ;
        }

        function register(requireResidentKey = false, getRequest = getRegisterRequest) {
          const credentialNickname = document.getElementById('credentialNickname').value;
          const username = document.getElementById('username').value;

          var request;

          return performCeremony({
            getRequest: urls => getRequest(username, credentialNickname, requireResidentKey),
            executeRequest: req => {
              request = req;
              return executeRegisterRequest(req);
            },
          })
          .catch((err) => {
            setStatus('Registration failed. Are you using a supported device/browser?');
            $('#submit').show();
            $('#status').addClass("message error");

            return rejected(err);
          });
        }

        $('#submit').click(function(e){
          e.preventDefault();
          $('#submit').hide();
          setStatus('Starting registration process...');
          $('#status').removeClass();
          register();
        });

        $('#credentialNickname').keypress(function(e) {
          if(e.keyCode == 13) {
            e.preventDefault();
            if ($('#credentialNickname').val().length > 0) {
              $('#submit').click();
            }
          }
        });

        $('#credentialNickname').keyup(function(e) {
          if ($('#credentialNickname').val().length > 0) {
            $('#submit').prop("disabled", false);
          } else {
            $('#submit').prop("disabled", true);
          }
        });
      });
    </script>
  </head>
  
  <body>
    <div id="main">
      <div id="left">
        <form>
          <div class="content-section">
            <h2>New device</h2>
            <div class="form-set">
              <label for="username">Username:</label>
              <input type="text" id="username"/>
            </div>
            <div class="form-set">
              <label for="credentialNickname">Give your device a nickname:</label>
              <input type="text" id="credentialNickname"/>
            </div>

            <button id="submit" type="button" class="active" disabled="disabled">Register device with WebAuthn<i class="button-icon-right fa fa-arrow-right"></i></button>
            <p id="status"></p>
          </div>
        </form>
      </div>
    </div>
  </body>
</html>
