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
            const { url: checkedUrl, prediction, whois } = mlResponse.data;
            mlPrediction = prediction || "No Response" ;
            // Whois = whois || "No Response";
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
            gsbResult = gsbResponse.data && gsbResponse.data.matches ? "⚠️ Warning! The URL is unsafe" : "✅ The URL is safe!";
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
        } catch (error) {
            console.error("VirusTotal API Error:", error.message);
        }

        //who is xml api call up
        try {
            let fullUrl = url;
            if (!fullUrl) throw new Error('URL parameter is required');
    
            // Ensure the URL has a protocol, otherwise add "https://"
            if (!fullUrl.startsWith('http://') && !fullUrl.startsWith('https://')) {
                fullUrl = 'https://' + fullUrl;
            }
    
            // Extract domain from the URL
            let hostname = new URL(fullUrl).hostname;
    
            // Remove "www." if present
            if (hostname.startsWith("www.")) {
                hostname = hostname.substring(4);
            }
    
            // Validate domain
            if (!hostname) throw new Error('Invalid URL');
    
            // WHOIS API call
            const apiKey = WHO_IS_XML_API_KEY;
            const whoisUrl = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${apiKey}&domainName=${hostname}&outputFormat=json`;
    
            const response_whois = await axios.get(whoisUrl)  || "No Result" ;
    
            // Send API response
            // res.json(response.data);
            console.log(response_whois)
    
        } catch (error) {
            console.error('Error:', error.message);
            // res.status(400).json({ error: error.message || 'Internal Server Error' });
        }
    

        // If Google Safe Browsing and VirusTotal detect nothing, set ML prediction to benign
        if (vtResult.malicious === 0 && vtResult.malicious < 2 ) {
            //mlPrediction = "benign";
        }
        if(vtResult.malicious ){
            //mlPrediction = "Malicious"
        }
        if(mlPrediction == "Phishing" && vtResult.malicious === 0){
            //mlPrediction = "benign"
        }
        console.log(Whois,mlPrediction,gsbResult,vtResult)
        return res.status(200).json({
            url,
            whois : response_whois,
            ml_prediction: mlPrediction,
            gsb_response: gsbResult,
            Virus_Total_response: vtResult
        });
        
    } catch (error) {
        console.error("Error in website analysis:", error.message);
        return res.status(500).json({ error: "Error in website analysis" });
    }
};
