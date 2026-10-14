function clearAll() {
    document.getElementById("msg").value = "";

    const resultBox = document.getElementById("result");
    resultBox.textContent = "";
    resultBox.className = "";
    resultBox.style.display = "none";
}

async function checkSpam() {
    
    const inputElement = document.getElementById("msg");
    const resultBox = document.getElementById("result");
    
    
    const text = inputElement.value.trim();

    
    if (!text) {
        alert("Please enter a message to analyze.");
        return;
    }

    resultBox.textContent = "Analyzing message...";
    resultBox.className = "";
    resultBox.style.display = "block";

    try {
        const response = await fetch("http://localhost:8080/api/classify", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ message: text }) 
        });

        if (!response.ok) {
            throw new Error("Server responded with status " + response.status);
        }

        const data = await response.json();

        if (data.prediction === "SPAM") {
            resultBox.className = "spam";
            
            let reasonsList = "";
            if (data.reasons && data.reasons.length > 0) {
                reasonsList = "<ul style='margin-top: 8px; margin-left: 20px; font-weight: normal;'>" + 
                              data.reasons.map(item => `<li>${item}</li>`).join("") + 
                              "</ul>";
            }

            resultBox.innerHTML = `
                <strong>Result: SPAM DETECTED</strong> (Score: ${data.score}/100)
                ${reasonsList}
            `;
        } else {
            resultBox.className = "ham";
            resultBox.innerHTML = `
                <strong>Result: NOT SPAM</strong> (Score: ${data.score}/100)
            `;
        }

    } catch (error) {
        console.error("Connection failed:", error);
        resultBox.className = "spam";
        resultBox.textContent = "Unable to connect to server. Ensure Spring Boot is running on port 8080.";
    }
}