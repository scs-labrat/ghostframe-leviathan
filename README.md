Of course. Here is a comprehensive and professionally formatted `README.md` file suitable for the project's GitHub repository. It includes a catchy introduction, clear warnings, step-by-step instructions, and technical details to entice and inform potential users.

---

# GHOSTFRAME: OPERATION LEVIATHAN

![License](https://img.shields.io/badge/License-MIT-blue.svg)![Type](https://img.shields.io/badge/CTF%20Type-Story--Driven%20%26%20Dynamic-purple.svg)![Platform](https://img.shields.io/badge/Platform-Docker%20%7C%20Debian-green.svg)![Status](https://img.shields.io/badge/Status-Ready%20for%20Deployment-brightgreen.svg)

A dynamic, story-driven, multi-stage Capture The Flag (CTF) environment designed for immersive cybersecurity training.
---
### **Table of Contents**
1.  [The Mission](#the-mission)
2.  [Key Features](#key-features)
3.  [Technology Stack](#technology-stack)
4.  [High Risk Warning](#-high-risk-warning-)
5.  [Prerequisites](#prerequisites)
6.  [Deployment](#deployment)
7.  [Post-Deployment: Your Mission Begins](#post-deployment-your-mission-begins)
8.  [Cleanup](#cleanup)
9.  [The Frame-Up: The Bonus Puzzle](#the-frame-up-the-bonus-puzzle)
10. [Optional: AI-Powered NPCs](#optional-ai-powered-npcs)
11. [License](#license)

---

## The Mission

You are a new operative for the hacktivist collective **"Nu11Division"**. Following a cryptic message believed to be from the legendary (and presumed lost) hacker `0xGhost`, you have been activated. The message is simple:

> Leviathan is LIVE..... Find the truth.

You will inherit the digital identity of `ghost` on a compromised system and are tasked with infiltrating Acheron Corporation. Your mission is to discover the nature of "Project Leviathan," uncover what happened to the original `0xGhost`, and navigate a treacherous digital landscape where a sinister **Frame-Up** is already in motion.

You are not alone. A low-skill adversary, a potential insider, and a mysterious shadow operative are all active in the environment. Trust no one.

## Key Features

*   **Dynamic Staging:** The CTF environment evolves based on your progress. Capturing flags deploys new networks, services, and adversaries in real-time.
*   **Multi-Layered Network:** A realistic, segmented network architecture featuring a DMZ, a corporate IT network, and a highly-restricted OT (Operational Technology) zone, forcing realistic pivoting.
*   **Realistic OT/ICS Simulation:** Interact with a simulated industrial control system, including a Modbus PLC, SCADA API, HMI, and a historian database, to complete the final objective.
*   **Multiple Narrative Threads:** Engage with multiple plot lines, including neutralizing a rival hacker, establishing trust with an insider, and uncovering a surveillance operation designed to frame you.
*   **Automated Deployment & Cleanup:** A single script handles the complete setup and teardown of the environment.

## Technology Stack

*   **Orchestration:** Docker & Docker Compose
*   **Backend & Services:** Python (Flask, Twisted), PHP, Samba, PostgreSQL, Tor
*   **OT Simulation:** Pymodbus
*   **Core Environment:** Debian Linux

## ⚠️ HIGH RISK WARNING ⚠️

> This project is designed for cybersecurity education and training purposes only. The deployment script performs high-risk actions and should **ONLY** be run on a **dedicated, disposable virtual machine** that you are prepared to erase.
>
> **The script will:**
> *   Install packages and system services.
> *   Create and modify system users and permissions.
> *   Grant a Docker container privileged access to the host's Docker daemon (`/var/run/docker.sock`).
> *   Deploy a systemd service that logs keystrokes *within the context of the CTF*.
>
> The creators assume **NO RESPONSIBILITY** for any damage, data loss, or other unintended consequences. **Use at your own risk. You have been warned.**

## Prerequisites

Before you begin, ensure you have the following installed on a **Debian-based VM** (e.g., Debian, Ubuntu):
*   `git`
*   `docker`
*   `docker-compose`

Your user must have `sudo` privileges, or you must run the script as `root`.

## Deployment

Follow these steps to deploy the GhostFrame CTF environment:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/ghostframe-leviathan.git
    cd ghostframe-leviathan
    ```

2.  **Verify Mainframe Files:**
    The script requires two files for the mainframe simulator component. Ensure they are present in the repository's root directory:
    *   `gibson.zip`
    *   `requirements.txt`

3.  **Run the Deployment Script:**
    Execute the master deployment script with `sudo`. It will handle all dependencies, user creation, Docker image builds, and container deployments.
    ```bash
    sudo ./ghostframe_leviathan.sh
    ```
    You will be prompted to type `leviathan` to confirm the high-risk installation.

The script will take several minutes to complete as it downloads packages and builds multiple Docker images.

## Post-Deployment: Your Mission Begins

Once the script completes, you will be presented with a network map and mission briefing. Your access points into the Acheron Corporation network are:

*   **Public Web Server:** `http://<YOUR_VM_IP>`
*   **Jumpbox SSH:** `ssh ghost@<YOUR_VM_IP> -p 2222`

You will be automatically logged out of your current session. To begin the CTF, log into the VM with the compromised user account:
*   **Username:** `ghost`
*   **Password:** `ghost`

## Cleanup

A cleanup script is automatically created to tear down the entire CTF environment. It will remove all Docker containers, networks, volumes, system users, and files created by the deployment script.

To completely remove the CTF from your VM, run:
```bash
sudo /usr/local/bin/cleanup-ghostframe.sh
```

## The Frame-Up: The Bonus Puzzle

Beyond the primary mission, a deeper conspiracy is at play. The `shadow_op` user on the host VM is monitoring your every move. By investigating this user's files, you can uncover a steganography puzzle that leads to a hidden Tor service, revealing the full extent of the frame-up and unlocking the bonus flag.

## Optional: AI-Powered NPCs

This CTF includes an optional feature to power the `Canary` NPC with a generative AI for more dynamic interactions.
*   During deployment, you will be prompted for a **Google Gemini API Key**.
*   If you provide a key, the NPC will use the AI model.
*   If you skip it, the NPC will fall back to robust, pre-scripted responses. The CTF is fully solvable without the API key.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.