# PhishGuard AI — Multimodal Phishing & Deepfake Detection

PhishGuard AI is a final-year B.Tech project that explores AI-assisted detection of suspicious and potentially manipulated content across multiple modalities: text, URLs, voice, images, and video. It also includes cross-modal fusion, explainability features, adversarial testing, and user-specific analysis history.

## Live Demo

**Deployed application:** http://129.154.245.149/

> **Note:** The demo currently uses HTTP, not HTTPS. Do not enter real passwords, personal information, or other sensitive data into the deployed demo. See [Real-Time Mode setup](#real-time-mode-microphone-and-screen-sharing) below if microphone or screen-sharing features are unavailable in Chrome.

## Features

- **Text and URL analysis** for phishing-related signals.
- **Voice analysis** for suspicious or potentially synthetic audio.
- **Image and video analysis** for visual phishing and deepfake-related signals.
- **Fusion Scan** to combine multiple modalities associated with the same incident into a unified assessment.
- **Explainability tools** to help inspect why some content was flagged.
- **Adversarial testing** to demonstrate obfuscation and defensive analysis.
- **User accounts and analysis history** in the web application.

These features support research and demonstrations; results should not be treated as a guarantee that content is safe or malicious.

## Run Locally in Visual Studio Code (Windows)

### Prerequisites

- Python installed on Windows.
- Visual Studio Code.
- The project files downloaded or cloned to your computer.

### Installation and startup

Open the project’s root folder in VS Code. The root folder is the one containing `README.md` and the `backend` folder. Open **Terminal → New Terminal**, then run these commands one at a time:

```powershell
cd backend
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

When the server starts, open this address in your browser:

**http://127.0.0.1:5000/**

Keep the VS Code terminal open while using the application. To stop the server, focus the terminal and press `Ctrl+C`.

### If PowerShell blocks environment activation

If PowerShell reports that script execution is disabled, run the following command in that terminal, then try activating the environment again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

This policy change applies only to the current PowerShell process. If setup still fails, check that Python is installed and that you are running the commands from the project root as described above.

## Real-Time Mode: Microphone and Screen Sharing

The deployed demo is served over HTTP. Chrome restricts microphone access and screen-capture APIs to secure contexts in many situations. The steps below are a **testing workaround**, not a recommended permanent production configuration.

1. Open **Google Chrome**.
2. In the address bar, open:

   ```text
   chrome://flags/#unsafely-treat-insecure-origin-as-secure
   ```

3. Find **Insecure origins treated as secure**.
4. Enter the following origin in its text field:

   ```text
   http://129.154.245.149
   ```

   Enter only the origin—do not add a page path or trailing route.

5. Change the dropdown for this flag to **Enabled**.
6. Click **Relaunch** to restart Chrome.
7. Reopen the deployed app: http://129.154.245.149/
8. When prompted, allow microphone access if you intend to use voice features.
9. For screen sharing, start the relevant Real-Time Mode action and choose the screen, window, or browser tab in Chrome's screen-sharing picker. Chrome requires the user to choose what to share; this permission is requested when screen sharing starts.

If Chrome does not show a permission prompt, check the site's permissions using the site controls beside the address bar. Availability can vary with Chrome versions and browser/device policies.

### Security warning

Treating an HTTP origin as secure does **not** encrypt the connection. Use this workaround only for a trusted demonstration environment, and do not submit confidential information. When finished, return to `chrome://flags/#unsafely-treat-insecure-origin-as-secure`, change the setting back to **Default**, and relaunch Chrome.

**Recommended long-term fix:** serve the application over HTTPS with a valid TLS certificate and configure the required browser permissions correctly.

## Project Structure

```text
.
├── README.md
└── backend/
    ├── app.py                 # Flask application entry point
    ├── templates/             # Web interface
    ├── static/                # Static and generated interface assets
    ├── data/                  # Test data and datasets
    ├── model/                 # Model artefacts
    ├── models/                # Additional model artefacts
    ├── requirements.txt       # Python dependencies
    ├── fusion_engine.py       # Cross-modal fusion logic
    ├── explainability.py      # Explainability utilities
    ├── adversarial.py         # Adversarial testing and defenses
    ├── routes_advanced.py     # Additional analysis routes
    ├── text_analyzer.py       # Text analysis
    ├── url_analyzer.py        # URL analysis
    ├── voice_detector.py      # Voice analysis
    ├── image_detector.py      # Image analysis
    └── video_detector.py      # Video analysis
```

## Important Notes

- Keep `.env` files, credentials, private user data, and local virtual environments out of version control.
- The `venv/` directory is created locally during setup and should not be uploaded to GitHub.
- Detection outputs are probabilistic and may be incorrect. Verify important decisions independently.
- This project is intended for academic, research, and demonstration purposes.

## Team / Academic Project

**Project:** PhishGuard AI  
**Type:** Final-year B.Tech project
