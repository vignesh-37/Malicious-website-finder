import axios from "axios";
import { URL } from "url";
import dotenv from "dotenv";

dotenv.config();

const VIRUSTOTAL_API_KEY = process.env.VirusTotal_api;
const GOOGLE_SAFE_BROWSING_API_KEY = process.env.Google_safeBrowse_api;
const WHO_IS_XML_API_KEY = process.env.whois_api_key;

export const checkURL = async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) {
            return res.status(400).json({ error: "No URL provided" });
        }

        const requestBody = {
            client: {
                clientId: "your-client-id",
                clientVersion: "1.0.0"
            },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url }]
            }
        };

        let mlPrediction = "No Response";
        let gsbResult = "No Response";
        let vtResult = "No Response";
        let Whois = "No Response";

        try {
            // ML Prediction
            const mlResponse = await axios.post("http://127.0.0.1:5000/predict", { url });
            mlPrediction = mlResponse.data.prediction || "No Response";
        } catch (error) {
            console.error("ML Prediction Error:", error.message);
        }

        try {
            // Google Safe Browsing API
            const gsbResponse = await axios.post(
                `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`,
                requestBody,
                { headers: { "Content-Type": "application/json" } }
            );
            gsbResult = gsbResponse.data && gsbResponse.data.matches
                ? "⚠️ Warning! The URL is unsafe"
                : "✅ The URL is safe!";
        } catch (error) {
            console.error("Google Safe Browsing Error:", error.message);
        }

        try {
            // VirusTotal API - Submit URL for scanning
            const vtResponse = await axios.post(
                "https://www.virustotal.com/api/v3/urls",
                new URLSearchParams({ url }),
                {
                    headers: {
                        "x-apikey": VIRUSTOTAL_API_KEY,
                        "Content-Type": "application/x-www-form-urlencoded"
                    }
                }
            );
            const scanId = vtResponse.data.data.id;

            // Retrieve the analysis result
            let vtResultResponse;
            let attempts = 0;
            do {
                await new Promise(resolve => setTimeout(resolve, 3000)); // Wait before retrying
                vtResultResponse = await axios.get(
                    `https://www.virustotal.com/api/v3/analyses/${scanId}`,
                    { headers: { "x-apikey": VIRUSTOTAL_API_KEY } }
                );
                attempts++;
            } while (vtResultResponse.data.data.attributes.status !== "completed" && attempts < 5);

            vtResult = vtResultResponse.data.data.attributes.stats;
            console.log(vtResult)
        } catch (error) {
            console.error("VirusTotal API Error:", error.message);
        }

        try {
            // Ensure URL is properly formatted
            let fullUrl = url;
            if (!fullUrl.startsWith("http://") && !fullUrl.startsWith("https://")) {
                fullUrl = "https://" + fullUrl;
            }
        
            // Extract domain from the URL
            let hostname = new URL(fullUrl).hostname;
            if (hostname.startsWith("www.")) {
                hostname = hostname.substring(4);
            }
        
            if (!hostname) throw new Error("Invalid URL");
        
            // WHOIS API call
            const whoisUrl = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHO_IS_XML_API_KEY}&domainName=${hostname}&outputFormat=json`;
        
            const response_whois = await axios.get(whoisUrl);
            const whoisData = response_whois.data?.WhoisRecord || {};
        
            // Extract key details
            Whois = {
                domain: whoisData.domainName || "Unknown",
                created_date: whoisData.createdDate || "Not available",
                updated_date: whoisData.updatedDate || "Not available",
                expires_date: whoisData.expiresDate || "Not available",
                registrant: {
                    organization: whoisData.registrant?.organization || "Not available",
                    contact_email: whoisData.registrant?.email || "Not available",
                    contact_phone: whoisData.registrant?.telephone || "Not available",
                    country: whoisData.registrant?.country || "Not available",
                },
                administrative_contact: whoisData.administrativeContact?.email || "Not available",
                technical_contact: whoisData.technicalContact?.email || "Not available",
                name_servers: whoisData.nameServers?.hostNames || [],
            };
        } catch (error) {
            console.error("WHOIS API Error:", error.message);
            Whois = { error: "Failed to retrieve WHOIS data" };
        }
        

        // If Google Safe Browsing and VirusTotal detect nothing, set ML prediction to benign
        if (vtResult.malicious === 0 && vtResult.malicious < 2) {
            // mlPrediction = "benign";
        }
        if (vtResult.malicious) {
            // mlPrediction = "Malicious";
        }
        if (mlPrediction === "Phishing" && vtResult.malicious === 0) {
            // mlPrediction = "benign";
        }

        // ✅ Send final response (ensures only one response is sent)
        return res.status(200).json({
            url,
            whois: Whois,
            ml_prediction: mlPrediction,
            gsb_response: gsbResult,
            Virus_Total_response: vtResult
        });

    } catch (error) {
        console.error("Error in website analysis:", error.message);
        return res.status(500).json({ error: "Error in website analysis" });
    }
};
