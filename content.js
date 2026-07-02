let popupShown = false;
let observerPaused = false;
let userDismissed = false;

function showWarning(findings, score, riskColor)
{
    let numericScore = parseInt(score);
    let riskLevel = "Low";

    if (numericScore >= 80) 
    {
        riskLevel = "High";
    } 
    else if (numericScore >= 40) 
    {
    riskLevel = "Medium";
    }
    
    let oldBox = document.getElementById("phishing-warning-box");
    if (oldBox) return;

    const warningBox = document.createElement("div");
    warningBox.id = "phishing-warning-box";

    const title = document.createElement("div");
    title.textContent = "🐱 PhishCat Integrity Alert";
    title.style.fontSize = "18px";
    title.style.fontWeight = "bold";
    title.style.marginBottom = "10px";

    const riskLevelText = document.createElement("div");
    riskLevelText.innerHTML = "<b>Risk Level:</b> " +   riskLevel;
    riskLevelText.style.marginBottom = "5px";

    const riskScoreText = document.createElement("div");
    riskScoreText.innerHTML = "<b>Risk Score:</b> " + score;
    riskScoreText.style.marginBottom = "10px";

    const issuesTitle = document.createElement("div");
    issuesTitle.innerHTML = "<b>Detected Issues:</b>";
    issuesTitle.style.marginBottom = "6px";

    const issueList = document.createElement("ul");
    issueList.style.paddingLeft = "18px";
    issueList.style.marginTop = "0";
    issueList.style.marginBottom = "10px";

    findings.forEach(item => 
    {
        const li = document.createElement("li");
        li.textContent = item;
        issueList.appendChild(li);
    });

    const note = document.createElement("div");
    note.textContent = "⚠️ Web component integrity violation detected. Do not submit sensitive information.";
    note.style.fontSize = "13px";
    note.style.color = "#555";
    note.style.marginBottom = "10px";

    const reportBtn = document.createElement("button");
    reportBtn.textContent = "Report Website";
    reportBtn.style.marginLeft = "10px";
    reportBtn.style.padding = "6px 10px";
    reportBtn.style.border = "none";
    reportBtn.style.background = "#457b9d";
    reportBtn.style.color = "white";
    reportBtn.style.borderRadius = "6px";
    reportBtn.style.cursor = "pointer";

    reportBtn.onclick = () => 
    {
        const currentURL = window.location.href;

        window.open(
            "https://safebrowsing.google.com/safebrowsing/report_phish/?url=" + currentURL,
            "_blank"
        );
    };

    const reportNote = document.createElement("div");
    reportNote.textContent = "You can report this site for further investigation.";
    reportNote.style.fontSize = "12px";
    reportNote.style.marginTop = "8px";

    const closeBtn = document.createElement("button");
    closeBtn.textContent = "Dismiss";
    closeBtn.style.padding = "6px 10px";
    closeBtn.style.border = "none";
    closeBtn.style.background = "#d90429";
    closeBtn.style.color = "white";
    closeBtn.style.borderRadius = "6px";
    closeBtn.style.cursor = "pointer";

    closeBtn.onclick = () => 
    {
    userDismissed = true;
    popupShown = false;
    warningBox.remove();
    };

    warningBox.appendChild(title);
    warningBox.appendChild(riskLevelText);
    warningBox.appendChild(riskScoreText);
    warningBox.appendChild(issuesTitle);
    warningBox.appendChild(issueList);
    warningBox.appendChild(note);
    warningBox.appendChild(reportNote);
    
    const btnContainer = document.createElement("div");
    btnContainer.style.marginTop = "10px";
    btnContainer.style.display = "flex";
    btnContainer.style.gap = "10px";

    btnContainer.appendChild(closeBtn);
    btnContainer.appendChild(reportBtn);
    
    warningBox.appendChild(btnContainer);

    warningBox.style.position = "fixed";
    warningBox.style.top = "20px";
    warningBox.style.right = "20px";
    warningBox.style.width = "320px";
    warningBox.style.background = "#ffffff";
    warningBox.style.color = "#333";
    warningBox.style.borderRadius = "12px";
    warningBox.style.padding = "15px";
    warningBox.style.boxShadow = "0 10px 30px rgba(0,0,0,0.2)";
    warningBox.style.fontFamily = "Segoe UI, sans-serif";
    warningBox.style.zIndex = "999999";
    warningBox.style.borderLeft = "6px solid " + riskColor;

    document.body.appendChild(warningBox);
    popupShown = true;
}

function checkPage() 
{
    if (observerPaused) return;

    const pageDomain = window.location.hostname;
    
    const trustedDomains = 
    [
    "safebrowsing.google.com",
    "google.com",
    "www.google.com",
    "chat.openai.com"
    ];
    
    if (trustedDomains.includes(pageDomain))
    {
        return;
    }
    
    const forms = document.querySelectorAll("form");
    const iframes = document.querySelectorAll("iframe"); //iframe detection

    let riskScore = 0;
    let findings = [];

    forms.forEach(form => 
    {
        const action = form.getAttribute("action");

        if (action) 
        {
            try 
            {
                const formDomain = new URL(action, window.location.href).hostname;

                if (formDomain !== pageDomain) //detection
                {
                    riskScore += 70;
                    findings.push("Form integrity violation: form action points to a different domain.");

                    if (!form.dataset.flagged) 
                    {
                        form.style.border = "3px solid red";
                        form.style.backgroundColor = "#ffe5e5";
                        form.dataset.flagged = "true";
                        
                        form.querySelectorAll("input, button").forEach(el => 
                        {
                        el.disabled = true;
                        }); //disable all inputs

                        const overlay = document.createElement("div");
                        overlay.textContent = "🚫 This form is blocked due to phishing risk";
                        overlay.style.position = "absolute";
                        overlay.style.top = "0";
                        overlay.style.left = "0";
                        overlay.style.width = "100%";
                        overlay.style.height = "100%";
                        overlay.style.background = "rgba(255,0,0,0.2)";
                        overlay.style.display = "flex";
                        overlay.style.alignItems = "center";
                        overlay.style.justifyContent = "center";
                        overlay.style.fontWeight = "bold";

                        form.style.position = "relative";
                        form.appendChild(overlay);

                        form.addEventListener("submit", function(e) //block submit 
                        {
                            e.preventDefault();

                            alert("🚫 This form has been blocked because it may send your data to a phishing website.");

                            showWarning(
                                ["Blocked suspicious form submission to different domain."],
                                "100%",
                                "#e63946"
                            );
                        });
                    }
                }
            } 
            catch (e) //invalid form detection
            {
                riskScore += 20;
                findings.push("Form action could not be verified.");
            }
        }
    });

    iframes.forEach(frame =>
    {
        const src = frame.getAttribute("src");

        if (src) // detect ANY iframe (for demo)
        {
            riskScore += 30;
            findings.push("Component integrity warning: external iframe detected.");

            if (!frame.dataset.flagged)
            {
                frame.style.border = "4px solid orange";
                frame.dataset.flagged = "true";
            }
        }
    });

    if (riskScore > 100) //risk calculation (combined all detection)
    
    {
        riskScore = 100;
    }


    let riskColor = "#2a9d8f"; // green (low risk)

    if (riskScore >= 80) 
    {
    riskColor = "#e63946"; // red (high risk)
    } 
    else if (riskScore >= 40) 
    {
    riskColor = "#f4a261"; // orange (medium risk)
    }
    
    if (riskScore > 0 && !popupShown && !userDismissed) //show alert or not
    
    {
        observerPaused = true;
        showWarning(findings, riskScore + "%", riskColor);
        setTimeout(() => 
        {
            observerPaused = false;
        }, 300);
    }
}

window.addEventListener("load", () => 
{
    setTimeout(checkPage, 500);

    const observer = new MutationObserver((mutations) => 
    {
        if (observerPaused) return;

        for (const mutation of mutations) 
        {
            if (
                mutation.target.id === "phishing-warning-box" ||
                (mutation.target.closest && mutation.target.closest("#phishing-warning-box"))
            ) 
            {
                return;
            }
        }

        checkPage();
    });

    observer.observe(document.body, 
    {
        attributes: true,
        childList: true,
        subtree: true
    });
});
