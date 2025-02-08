import axios from "axios";
import {URL} from "url"
import dotenv from "dotenv";
import { parse } from "path";

dotenv.config();

const VIRUSTOTAL_API_KEY = process.env.VirusTotal_api;
const GOOGLE_SAFE_BROWSING_API_KEY = process.env.Google_safeBrowse_api;
const WHOIS_API_KEY = process.env.whois_api_key;

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

        let mlprediction = null;
        let gsb_Result = null;
        let VT_result = null;
        let domainInfo = null

        try {
            // Get ML Prediction (Only extract data)
            const mlResponse = await axios.post("http://127.0.0.1:5000/predict", { url });
            mlprediction = mlResponse.data; 

            // Check with Google Safe Browsing API
            const gsbResponse = await axios.post(
                `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`,
                requestBody,
                { headers: { "Content-Type": "application/json" } }
            );

            if (gsbResponse.data && gsbResponse.data.matches) {
                gsb_Result = "⚠️ Warning! The URL is unsafe";
            }
            else{
                gsb_Result = "✅ The URL is safe!"
            }

            const vtUrl = "https://www.virustotal.com/api/v3/urls";

            const VT_responce = await axios.post(
                vtUrl,
                new URLSearchParams({ url }),
                {
                    headers: {
                        "x-apikey": VIRUSTOTAL_API_KEY,
                        "Content-Type": "application/x-www-form-urlencoded"
                    }
            }   
            );

            const scanId = VT_responce.data.data.id; // Extract the scan ID

            // Step 2: Get scan results using the ID
            const VT_resultResponse = await axios.get(
            `https://www.virustotal.com/api/v3/analyses/${scanId}`,
            { headers: { 'x-apikey': VIRUSTOTAL_API_KEY } }
        );
            console.log(VT_resultResponse)
            VT_result = VT_resultResponse.data;

            
            const match = url.match(/^https?:\/\/(?:www\.)?([^\/]+)/);
            const domain =  match ? match[1] : null; // Return the domain, or null if no mat

            const whois_response = await axios.get(`https://rdap.org/domain/${domain}`);

            // Helper function to get vCard data from the RDAP response
            function getVCardData(data, field) {
            if (data.vcardArray && data.vcardArray[0] && data.vcardArray[0][1]) {
            const vCard = data.vcardArray[0][1];
            for (const item of vCard) {
                if (item[0] === field) {
                    return item[1];
                }
            }
        }
    return null; // Return null if the field is not found
}

            const { data } = whois_response;
            console.log(whois_response)    
            domainInfo = {
                domainName: data.ldhName || "Not Available",
                domainHandle: data.handle || "Not Available",
                organization: getVCardData(data, "org") || "Not Available",
                fullName: getVCardData(data, "fn") || "Not Available",
                registrationDate: data.events.find(event => event.eventAction === 'registration')?.eventDate || "Not Available",
                expirationDate: data.events.find(event => event.eventAction === 'expiration')?.eventDate || "Not Available",
                status: data.status.length ? data.status : ["Not Available"],
                nameservers: data.nameservers ? data.nameservers.map(ns => ns.name).filter(Boolean) : ["Not Available"]
            };
            //domainInfo = JSON.stringify(domainInfo, null, 2);                
        

        } catch (error) {
            console.error("Error in ML Prediction or Google Safe Browsing or VirusTotal api -  Check:", error);
            return res.status(400).json({ error: "Error on ML Prediction or GSB Check" });
        }


        return res.status(200).json({
            url,
            gsb_response: gsb_Result,
            ml_prediction: mlprediction,
            Virus_Total_responce:VT_result.data.attributes.stats, 
            WHOIS_Result : domainInfo
        });

    } catch (error) {
        console.error("Error in website analysis:", error);
        res.status(500).json({ error: "Error in website analysis" });
    }
};
