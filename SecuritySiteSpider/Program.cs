using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.RegularExpressions;


namespace SecuritySiteSpider
{
    public static class Program
    {
        /*
         * Description:
         * This is a PoC that spiders websites while analyzing their response headers and describes the webservers security ONLY based on those headers. 
         * This ignores all privacy related issues such as referrer-policy
         * This is just something I made because I like spiders and it helps me to learn and rememeber if I codify my knowledge
         * Note: I build this on what I found on the internet, I didn't look at all of the standards/spec's/RFC's so there's always going to be 
         * new/missing/funky stuff (I prefer to see what's the the real world).
         * 
         * ToDo:
         * - Explain that the lack of a sandbox CSP will mean that a loaded iframe can prompt a download
         * - Print description about the Cookie and it's attributes
         * - Highlight non-standard HTTP Headers allowed in 'Access-Control-Allow-Headers'. A webserver is telling you they allow it... and it's custom so it's probably ripe for abuse
         * - Scrape the page because 
         *      the meta HTML tag can contain the Content Security Policy (and probably other things). (though not Content-Security-Policy-Report-Only).
         *          Ex: <meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">
         *          https://web.dev/fixing-mixed-content/ says "Policies are combined by taking the intersection of the policies; that is to say, each policy after the first can only further restrict the allowed content, not broaden it."
         *      crossorigin attribute can be in the script tag - "anonymous" and "use-credentials" (aka cookie)
         * - Store everything in a Log File
         * - Create better method to find links
         * - If given just a path, just discard it
         * - Load url list from file
         * - Look at https://developer.mozilla.org/en-US/docs/Glossary/CORS-safelisted_response_header
         * - Store everything in a 'mark as interesting' feature
         * - Let me google that for you
         * - Store everything in a DataBase
         * - Somehow Trigger the accept cookie
         * - print non-standard headers: https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
         * 
         * Ideas:
         * - Make a list of setFrameOptions not setting their value, and look up on hackerone
         * - We could build a web of trust
         * - Submit every URL to an analzer to see if the domain host content for us (like pastebin, or CDN), and see if VT has anything on it
         * - wget mirror -> Create a Content-Security-Policy that won't break anything
         *      Is there an easy way to drive the browser, and get the Console errors?
         *      Note: SVG images seem to require the 'data:'
         *      Basics: Xss_NoMimeSniffing, reffer policy set to send no data, 
         * 
         * Looks like someone has already done this: 
         * https://github.com/researchapps/url-headers
         * https://httpschecker.net/how-it-works#httpsChecker
         * https://github.com/bramus/mixed-content-scan
         * 
         * Interesting security features:
         * https://www.openstreetmap.org/?mlat=22.4449&amp;mlon=114.0263#map=15/22.4449/114.0263
         * https://www.mapquest.com/search/results?query=Gas
         * https://www.washingtonpost.com/
         * https://medlineplus.gov/
         * https://fun.chicagotribune.com/game/tca-jumble-daily (XSS-protection set to 0)
         * https://www.startribune.com/local/ allow-headers & methods & creds
         * http://www.mozilla.com/ many content-security-policies set
         * https://www.pinterest.com many content-security-policies set
         * https://duckduckgo.com/
         * http://www.usatoday.com/sports/fantasy/football/
         * https://www.nytimes.com/column/thomas-l-friedman
         * */

        public static bool printDefaultFailures = true;

        // This is just a simple data class to contain the default security state
        // as dictated as the headers state. I'm basiclly doing this to codify my 
        // own knowledge. This is not meant for other people
        class SiteSecurityState
        { // ToDo: Change class name to WebSiteSecurityState or something more appropreiate

            // HSTS was created to combat SSL Strip: https://www.secplicity.org/2019/11/05/hsts-a-trivial-response-to-sslstrip/#:~:text=HSTS%20tries%20to%20fix%20the,to%20a%20genuine%20HTTP%20website.
            private bool hsts = false;
            private bool hsts_subdomains = false;
            private bool hsts_preload = false;

            // x-frame-options
            private bool canBeEmbedded = true;
            private List<String> embeddedList = new List<String>();

            // XXS
            private bool Xss_protection = false;
            private bool Xss_blocking = false;
            private bool Xss_reporting = false;
            private bool Xss_NoMimeSniffing = false;    // https://www.coalfire.com/the-coalfire-blog/mime-sniffing-in-browsers-and-the-security




            // CSP
            private bool csp = false; 
            private bool csp_upgrade_insecure_requests = false; 
            private bool csp_img_src = false;
            private List<String> csp_img_src_List = new List<String>();
            private bool csp_script_src = false;
            private List<String> csp_script_src_List = new List<String>();
            private bool csp_form_action = false;
            private List<String> csp_form_action_List = new List<String>();
            private bool csp_style_src = false;
            private List<String> csp_style_src_List = new List<String>();



            // Cookie
            private bool cookie = false;
            private bool cookie_httponly = false;
            private bool cookie_secure = false;     // Will only be honored if this was given over an HTTPS request
            private bool cookie_domain = false;
            private bool cookie_strict = false;
            private bool cookie_lax = false;
            private bool cookie_none = false;




            override
            public string ToString()
            {
                string sumString = "";  // This is dumb. I have no idea why I did it like this. Note: don't code while tired

                // Cookie Security
                if (cookie)
                {
                    sumString += "- ";
                    if (cookie_httponly)
                    {
                        sumString += "The page's javascript will not be able to access the cookie";
                    }
                    else
                    {
                        sumString += "The page's javascript WILL be able to access the cookie";
                    }

                    if (cookie_secure)
                    {
                        // sumString += "The browser will not leak the cookie over an http connection";
                    }
                    else
                    {
                        if (csp && !csp_upgrade_insecure_requests)
                        {
                            sumString += " and the browser WILL leak the cookie over an http connection";
                        }
                        
                    }

                    if (cookie_domain)
                    {
                        
                        sumString += " and the cookie will always be sent back to the original site and subdomains";
                    }
                    sumString += ". ";

                    // Lax is the default
                    if (!cookie_none && !cookie_strict && !cookie_none)
                        cookie_lax = true;

                    if (cookie_none)
                    {
                        if (!cookie_secure)
                        {
                            cookie_lax = true;
                        }
                        else
                        {
                            // "The browser will not leak the cookie over an http connection" AND... coming from another site will also work
                            sumString += "The cookie will only be sent back to the original site but NOT when a user clicks a link from another site to here (aka no Cross Site Requests, aka no CSRF)";
                        }
                    }

                    if (cookie_strict)
                    {
                        sumString += "The cookie will only be sent back to the original site but NOT when a user clicks a link from another site to here (midigating XSS/Phishing and  Cross Site Requests from sites)";
                    }
                    if (cookie_lax)
                    {
                        sumString += "The cookie will always be sent back to the original site on initial GET/POST request (so Cross Site Requests are allowed, so if you visit a phishing site, it could make a request to this site)";
                    }
                    sumString += ".\n";
                }

                // CSP
                sumString += "- ";
                sumString += "If this connection is over HTTPS the browser will not load anything over HTTP (Cookies should be safe from leaking over an HTTP connection) ";
                if (csp)
                {
                    if (!csp_upgrade_insecure_requests)
                        sumString += " but if there are any HTTP requests the browser will load them over HTTPS (or fail trying). ";
                    // if the resource is not available over HTTPS, the upgraded request fails and the resource is not loaded.
                    // cascades into <iframe> documents, ensuring the entire page is protected.
                    if (csp_script_src)
                    {
                        sumString += "\n\tThe browser will only render JavaScript from: ";
                        foreach (string uri in csp_script_src_List)
                        {
                            if(uri.ToLower().Trim() == ""   || uri.ToLower().Trim() == "'unsafe-inline'"  || uri.ToLower().Trim() == "'unsafe-eval'")
                            {
                                // Don't print these 
                            } else
                            {
                                sumString += "\n\t\t";
                                if (uri.ToLower().Trim() == "https:" || uri.ToLower().Trim() == "*")
                                    sumString += "EVERYWHERE: " + uri;
                                else
                                    sumString += uri;
                            }
                            
                        }
                        if (!Xss_NoMimeSniffing)
                        {
                            sumString += "\n\t\t" + "The browser also might confuse some html or text for javascript";
                        }
                    } else
                    {
                        sumString += "\n\tThe browser will render JavaScript from ANYWHERE on this site";
                    }


                    if (csp_img_src)
                    {
                        sumString += "\n\tThe browser will only load images from: ";
                        foreach (string uri in csp_img_src_List)
                        {
                            sumString += "\n\t\t";
                            if (uri.ToLower().Trim() == "https:" || uri.ToLower().Trim() == "*")
                                sumString += "EVERYWHERE: " + uri;
                            else
                                sumString += uri;
                        }
                        if (!Xss_NoMimeSniffing)
                        {
                            sumString += "\n\t\t" + "The browser also might confuse an image for javascript";
                        }
                    }
                    else
                    {
                        sumString += "\n\tThe browser will load images from ANYWHERE on this site";
                    }




                    if (csp_form_action)
                    {
                        sumString += "\n\tThe browser will only allow forms to target: ";
                        foreach (string uri in csp_form_action_List)
                        {
                            sumString += "\n\t\t";
                            if (uri.ToLower().Trim() == "https:" || uri.ToLower().Trim() == "*")
                                sumString += "EVERYWHERE: " + uri;
                            else
                                sumString += uri;
                        }
                    }
                    else
                    {
                        sumString += "\n\tThe server will process form POSTing to any URL";
                    }
                    
                    
                    if (csp_style_src)
                    {
                        sumString += "\n\tThe browser will only allow styles loaded from: ";
                        foreach (string uri in csp_style_src_List)
                        {
                            if (uri.ToLower().Trim() == "" || uri.ToLower().Trim() == "'unsafe-inline'" || uri.ToLower().Trim() == "'unsafe-eval'")
                            {
                                // Don't print these 
                            }
                            else
                            {
                                sumString += "\n\t\t";
                                if (uri.ToLower().Trim() == "https:" || uri.ToLower().Trim() == "*")
                                    sumString += "EVERYWHERE: " + uri;
                                else
                                    sumString += uri;
                            }
                        }
                        if (!Xss_NoMimeSniffing)
                        {
                            sumString += "\n\t\t" + "The browser also might confuse a stylesheet for javascript";
                        }
                    }
                    else
                    {
                        sumString += "\n\tThe server will load stylesheets from any URL on this site";
                    }
                } else
                { // if there is no Content Security Policy found
                    sumString += "\n- There site has NO Content Security Policy SO...";
                    sumString += "\n\tThe browser will render JavaScript from ANYWHERE on this site";
                    sumString += "\n\tThe browser will load images from ANYWHERE on this site";
                    sumString += "\n\tThe server will load stylesheets from any URL on this site";
                }
                sumString += ".\n";

                // HSTS
                sumString += "- ";
                if (hsts)
                {
                    if (hsts)
                        sumString += "Once this site has been visited via HTTPS, all resources will be loaded over https";
                    if (hsts_subdomains)
                        sumString += " including subdomains";
                    if (hsts_preload)
                        sumString += " and this will eventually happen without that first connection to the server because it's going on the preload list";
                   
                } else
                {
                    sumString += "This site can be loaded over HTTP (SslStripping is possible if HTTPS exists)";
                }
                sumString += ".\n";


                // x-frame-options
                
                if (canBeEmbedded)
                {
                    
                    if (embeddedList.Count == 1)
                    {
                        if (embeddedList[0].ToLower().Contains("sameorigin"))
                        {
                            // but can only embed from it's own pages
                        }
                    }
                    else
                    {
                        sumString += "- ";
                        sumString += "This site can be embedded in an iframe, so phishing/Clickjacking might be possible";
                        if(embeddedList.Count == 0)
                        {
                            sumString += " from ANYWHERE";
                        } else
                        {
                            sumString += " from these sites: ";
                            foreach (string site in embeddedList)
                            {
                                sumString += " " + site + " ";
                            }
                            
                        }
                        sumString += ".\n";
                    }
                }
                else
                {
                    sumString += "- This site can NOT be embedded in an iframe.\n";
                }



                // XSS
                sumString += "- ";
                if (Xss_NoMimeSniffing)
                {
                    sumString += "The browser will NOT render JS unless the MIME type is 'text/javascript'";
                }
                else
                {
                    sumString += "The browser might render some content form this site as JavaScript so XSS might be a little more easy";
                }
                /*
                if(Xss_protection || Xss_blocking)
                {
                    sumString += "The XSS Protection header is present but this has been retired by modern browsers. ";
                }
                if (Xss_reporting)
                {
                    sumString += "The XSS Reporting header ";
                }*/
                sumString += ".\n";


                return sumString;
            }

            // ToDo: Make a test function canLoadScriptsFrom("google.com"), do the same for images, fonts, frame, etc.
            internal void setCookieParam(string value)
            {
                cookie = true;
                string param = value.ToLower();
                switch (param)
                {   // TODO: Look up the offical standard instead of just relying on only real world web scrapping 
                    // TODO: Set these values below and the defaults above
                    case string s when s.StartsWith("__secure-"):
                        // If a cookie name has this prefix, it's accepted in a Set-Cookie header only if it's marked with the Secure attribute and
                        // was sent from a secure origin. This is weaker than the __Host- prefix.
                        break;
                    case string s when s.StartsWith("__host-"):
                        // If a cookie name has this prefix, it's accepted in a Set-Cookie header only if it's also marked with the Secure attribute,
                        // was sent from a secure origin, does not include a Domain attribute, and has the Path attribute set to /.
                        // This way, these cookies can be seen as "domain-locked".
                        break;
                    case string s when s.StartsWith("path"):
                        break;
                    case string s when s.StartsWith("secure"):
                        cookie_secure = true;
                        break;
                    case string s when s.StartsWith("samesite"):
                        if (param.Contains("none"))
                            cookie_none = true;
                        if (param.Contains("lax"))
                            cookie_lax = true;
                        if (param.Contains("strict"))
                            cookie_strict = true;
                        break;
                    case string s when s.StartsWith("max-age"): 
                        // TODO: Look for REALLY long lasting cookie's
                        break;
                    case string s when s.StartsWith("domain"):
                        cookie_domain = true;
                        break;
                    case string s when s.StartsWith("expires"):
                        break;
                    case string s when s.StartsWith("httponly"):
                        // Due to backwards compatability, Cookies will also be sent to subdomains, this will prevent that
                        cookie_httponly = true;
                        break;
                    case string s when s.Trim() == "":
                        break;
                    default:
                        if (printDefaultFailures)
                            Console.WriteLine("Non-standard Cookie component: " + value);
                        break;
                }
                
            }

            internal void setCSPParam(string key, string value)
            {
                csp = true;
                switch (key.ToLower())
                {   // TODO: Look up the offical standard instead of just relying on only real world web scrapping 
                    // TODO: Set these values below and the defaults above
                    case string s when s.StartsWith("upgrade-insecure-requests"):
                        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/upgrade-insecure-requests
                        csp_upgrade_insecure_requests = true;
                        break;
                    case string s when s.StartsWith("block-all-mixed-content"):
                        // Deprecated. The above (upgrade-insecure-requests) is evaluated first
                        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/block-all-mixed-content
                        // I think this is default behavior, "all mixed content is now blocked if it can't be autoupgraded"
                        break;
                    case string s when s.StartsWith("report-uri"):
                        // Deprecated. in favor of report-to
                        break;
                    case string s when s.StartsWith("report-to"):
                        // Deprecated. in favor of report-to
                        break;
                    case string s when s.StartsWith("frame-ancestors"):
                        break;
                    case string s when s.StartsWith("child-src"):
                        break;
                    case string s when s.StartsWith("img-src"):
                        csp_img_src = true;
                        foreach (string uri in value.Split(' '))
                            csp_img_src_List.Add(uri);
                        break;
                    case string s when s.StartsWith("script-src"):
                        csp_script_src = true;
                        foreach (string uri in value.Split(' '))
                            csp_script_src_List.Add(uri);
                        break;
                    case string s when s.StartsWith("font-src"):
                        break;
                    case string s when s.StartsWith("default-src"):
                        break;
                    case string s when s.StartsWith("frame-src"):
                        break;
                    case string s when s.StartsWith("connect-src"):
                        break;
                    case string s when s.StartsWith("style-src"):       // TODO: Figure out if I can execute javascript via styles
                        csp_style_src = true;
                        foreach (string uri in value.Split(' '))
                            csp_style_src_List.Add(uri);
                        break;
                    case string s when s.StartsWith("require-trusted-types-for"):
                        break;
                    case string s when s.StartsWith("object-src"):
                        break;
                    case string s when s.StartsWith("base-uri"):
                        break;
                    case string s when s.StartsWith("worker-src"):
                        break;
                    case string s when s.StartsWith("media-src"):
                        break;
                    case string s when s.StartsWith("manifest-src"):
                        break;
                    case string s when s.StartsWith("sandbox"):
                        break;
                    case string s when s.StartsWith("form-action"):
                        csp_form_action = true;
                        foreach (string uri in value.Split(' '))
                            csp_form_action_List.Add(uri);
                        break;
                    case string s when s.Trim() == "":
                        break;
                    default:
                        if (printDefaultFailures)
                            Console.WriteLine("Need to process CSP Param: " + key);
                        break;
                }
            }

            internal void processGenericSecurityHeader(string key, string value)
            {
                switch (key.ToLower())
                {

                    case "x-frame-options":
                        // Can it be embedded in an iframe
                        setFrameOptions(value);
                        break;
                    case "x-xss-protection":     
                        // This is in the ignore list for now because it's been retired by modern browsers
                        processXssProtection(value);
                        break;
                    case "x-content-type-options":
                        processMineTypeXssProtection(value);
                        break;
                    case "strict-transport-security":
                        processHSTS(value);
                        break;
                    case "referrer-policy":
                        // This is in the ignore list for now because it's only about privacy
                        // If the referrer URL had sensitive information, then the new website could get it
                        // google.com/changepassword.php?newpass=changeme then you clicked a link to evil.com, it would see that previous URL
                        processReferrerPolicy(value);
                        break;

                    case "report-to":
                        // This might be intersting to play with at some point
                        break;

                    // CORS Headers
                    case "access-control-allow-origin":
                        // This only tells the browser that if this page is being accessed, it should only be from the given resoruce
                        // But... we're not a well behaved browser :-)
                        // See https://stackoverflow.com/questions/10636611/how-does-access-control-allow-origin-header-work
                        // If the value is '*' then any page can load resources from here (here = the server that told you this)
                        break;
                    case "access-control-allow-credentials":
                        break;
                    case "access-control-allow-methods":
                    case "access-control-allow-method":
                        break;
                    case "access-control-allow-headers":
                        break;

                    // Related but different 'policy' I guess?
                    case "cross-origin-opener-policy":
                        break;
                    case "cross-origin-embedder-policy":
                        break;
                    case "cross-origin-resource-policy":
                        break;

                    // controls third-party access to features such as camera, microphone and geolocation
                    case "permissions-policy":
                        // Example: Embed an iframe from a third party site but don’t allow the third-party site to be able to access the camera of my website visitor 
                        // Control the default behavior of ‘autoplay’ on mobile and third-party videos
                        // Block the use of outdated APIs like document.write and synchronous XHR
                        break;


                    default:
                        if(printDefaultFailures)
                            Console.WriteLine("What is the default value of " + key.ToLower());
                        break;
                }
            }

            private void processReferrerPolicy(string value)
            {
                // ToDo: look up the standard
                if (printDefaultFailures)
                    Console.WriteLine("What is the default value of " + value);
            }

            private void processMineTypeXssProtection(string value)
            {
                if (value.ToLower().Contains("nosniff")){
                    Xss_NoMimeSniffing = true;
                }
                else
                {
                    Console.WriteLine("Error: x-content-type-options should only be able to have 'nosniff' and it has: " + value);
                }
            }
            private void processXssProtection(string values)
            {
                // This is retired: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
                foreach (string value in values.Split(';'))
                {
                    if (value.ToLower().Trim() == "1")
                    {
                        Xss_protection = true;
                    }
                    else if (value.ToLower().Trim() == "0")
                    {
                        Xss_protection = false;
                    }
                    else if (value.ToLower().Trim() == "")
                    {
                        Xss_protection = false; // I don't know I guess
                    }
                    else if (value.ToLower().Contains("mode=block"))
                    {
                        Xss_blocking = true;
                    }
                    else if (value.ToLower().Contains("report="))
                    {
                        Xss_reporting = true;
                    }
                    else
                    {
                        if (printDefaultFailures)
                            Console.WriteLine("No XSS Protection known value: " + value);
                    }

                }
                
                    
            }

            private void processHSTS(string value)
            {
                value = value.ToLower();
                // This is a little dumb because if it's over HTTP, it's not honrored lol
                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
                if (value.Contains("max-age") && !value.Contains("max-age=0"))  // 0 means to clear the policy client sides
                {
                    hsts = true;

                    if (value.Contains("includesubdomains"))
                    {
                        hsts_subdomains = true;
                    }
                    if (value.Contains("preload"))
                    {
                        hsts_preload = true;
                    }
                }
                


                //if (hsts)
                //{
                //    if (printDefaultFailures)
                //        Console.WriteLine("No HSTS known value: " + value);
                //}


            }

            internal void setFrameOptions(string value)
            {
                switch (value.ToLower())
                {   // TODO: Look up the offical standard instead of just relying on only real world web scrapping 
                    case string s when s.StartsWith("deny"):
                        canBeEmbedded = false;
                        break;
                    case string s when s.StartsWith("sameorigin"):
                        embeddedList.Add(value);
                        break;
                    case string s when s.StartsWith("allow-from"):
                        embeddedList.Add(value);
                        break;
                    case string s when s.Trim() == "": 
                        // I don't know how, but some sites just don't supply anything so (Chrome at least) ignores it for now
                        canBeEmbedded = true;
                        break;
                    default:
                        if(printDefaultFailures)
                            Console.WriteLine("Need to process x-frame-options value: " + value);
                        break;
                }
            }
        } // end class

        public struct LinkItem
        {
            public string Href;
            public string Text;

            public override string ToString()
            {
                return Href; // + "\n\t" + Text;
            }
        }

        static class LinkFinder
        {
            public static List<LinkItem> Find(string file)
            {
                List<LinkItem> list = new List<LinkItem>();

                // 1.
                // Find all matches in file.
                MatchCollection m1 = Regex.Matches(file, @"(<a.*?>.*?</a>)",
                    RegexOptions.Singleline);

                // 2.
                // Loop over each match.
                foreach (Match m in m1)
                {
                    string value = m.Groups[1].Value;
                    LinkItem i = new LinkItem();

                    // 3.
                    // Get href attribute.
                    Match m2 = Regex.Match(value, @"href=\""(.*?)\""",
                        RegexOptions.Singleline);
                    if (m2.Success)
                    {
                        i.Href = m2.Groups[1].Value;
                    }

                    // 4.
                    // Remove inner tags from text.
                    string t = Regex.Replace(value, @"\s*<.*?>\s*", "",
                        RegexOptions.Singleline);
                    i.Text = t;

                    list.Add(i);
                }
                return list;
            }
        }





        static int Main(string[] args)
        {
            List<string> visited = new List<string>();
            Queue<string> links = new Queue<string>();
            //links.Enqueue("https://www.nytimes.com/subscription/dg-cookie-policy/cookie-policy.html");
            //links.Enqueue("https://www.nytimes.com/column/thomas-l-friedman");
            links.Enqueue("https://refdesk.com/");
            //links.Enqueue("https://sdb.tools/");
            //links.Enqueue("https://www.openstreetmap.org/?mlat=22.4449&amp;mlon=114.0263#map=15/22.4449/114.0263");
            //links.Enqueue("https://www.mapquest.com/search/results?query=Gas");
            //links.Enqueue("https://www.washingtonpost.com/");
            //links.Enqueue("https://medlineplus.gov/");
            //links.Enqueue("https://fun.chicagotribune.com/game/tca-jumble-daily");
            //links.Enqueue("https://www.startribune.com/local/");
            //links.Enqueue("http://www.mozilla.com/");
            //links.Enqueue("https://www.pinterest.com");
            //links.Enqueue("https://duckduckgo.com/");
            //links.Enqueue("http://www.usatoday.com/sports/fantasy/football/");



            while (links.Count > 0)
            {
                ShuffleQueue(links); // TODO: disable suffling if reading from a file
                string site = links.Dequeue();
                if (visited.Contains(site))
                {
                    continue;
                }
                System.Console.WriteLine("Scrapping server headers from " + site);

                WebClient web = new WebClient();
                string html = "";
                try
                {
                    html = web.DownloadString(site);
                } catch(Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    System.Console.WriteLine("Error: " + ex.Message);
                    Console.ForegroundColor = ConsoleColor.Gray;
                    continue;
                }
                visited.Add(site);


                // Extract Headers
                WebHeaderCollection myWebHeaderCollection = web.ResponseHeaders;

                //Normalize them both and add them to the tuple list
                var pageAttributesOrignial = new List<Tuple<string, string>>();
                var pageAttributes = new List<Tuple<string, string>>();
                foreach (string key in myWebHeaderCollection.AllKeys)
                {
                    string value = myWebHeaderCollection[key];
                    pageAttributesOrignial.Add(Tuple.Create(key, value));
                    pageAttributes.Add(Tuple.Create(key.ToLower(), value.ToLower()));
                }


                // Extract Meta tags
                // <meta name="keywords" content="HTML, CSS, JavaScript">
                Regex rx = new Regex("<meta.*name.*=\"(.*)\".*content.*=\"(.*)\">",
                    RegexOptions.Compiled | RegexOptions.IgnoreCase);
                MatchCollection matches = rx.Matches(html);
                foreach (Match match in matches)
                {
                    GroupCollection groups = match.Groups;
                    string key = groups[1].ToString();
                    string value = groups[2].ToString();
                    pageAttributesOrignial.Add(Tuple.Create(key, value));
                    pageAttributes.Add(Tuple.Create(key.ToLower(), value.ToLower()));
                }

                SiteSecurityState page = new SiteSecurityState();



                foreach ((string key, string value) in pageAttributes)
                {

                }

                for (int i = 0; i < myWebHeaderCollection.Count; i++)
                {
                    // My "Don't print" list
                    // ToDo: Make this into a swtich case, list, or something less obnoxious 
                    if (
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("server") ||           // This might be fun 
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-client-ip") ||           // This might be fun 
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-powered-by") ||     // this might be fun
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-content-powered-by") ||     // this might be fun
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-served-by") ||     // this might be fun
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("served-by") ||     // this might be fun
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-servedbyhost") ||     // this might be fun - ::ffff:127.0.0.1
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-hosted-by") ||     // this might be fun to map
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-bbackend") ||     // this might be fun
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-backend") ||     // this might be fun
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-datacenter") ||     // this might be fun
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-url") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-host") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-pbs-appsvrip") ||     // Bug: leaking internal IP info found on https://www.pbs.org/newshour/
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-pbs-") ||

                        // Info about me (aka creepy)
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-dbg-gt") ||     
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-true-client-ip") ||     

                        // Proxy Related
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-forwarded-for") ||     // this might be fun
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("via") ||     // this might be fun

                        // This might change the sites response format
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("vary") ||     
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-ua-compatible") ||     

                        // CloudFlare
                        myWebHeaderCollection.GetKey(i).ToLower().StartsWith("cf-") ||
                        myWebHeaderCollection.GetKey(i).ToLower().StartsWith("x-turbo-charged-by") ||

                        // AWS
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-amz-cf-pop") ||      
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-amz-cf-id") ||      
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-amz-version-id") ||      
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-amz-id-2") ||      
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-amz-request-id") ||      
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-amz-meta-uncompressed-size") ||   
                        
                        // Fastly
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("fastly-original-body-size") ||      

                        // Security related but don't really matter
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("expect-ct") ||  // Cert transparency

                        // CMS's
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-drupal-cache") ||  // Cert transparency
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("wpx") ||   // I think it's a wordpress site

                        // Interesting
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("nel") ||   // Network Error Logging (404's and such)
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("accept-ranges") ||   // resume downloads from a certain byte offset

                          // No documentation, don't seem to matter:
                          // x-gen-mode
                          // x-hnp-log
                          // x-ads


                          myWebHeaderCollection.GetKey(i).ToLower().Contains("x-origin-time") ||     
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("origin-trial") ||     // washingtonpost.com
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("x-xss-protection") ||     // this is on the ignore list because it's been retired by modern browsers
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-permitted-cross-domain-policies") ||  // used to permit cross-domain requests from Flash and PDF documents
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-download-options") ||     // just an IE-8 thing
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("referrer-policy") ||        // just a privacy thing https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy 
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("content-type") ||  
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("akamai-grn") ||     
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-cdn") ||     
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-route") ||       
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-origin-cache") ||     
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-varnish") ||     
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("pragma") ||     
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-gt-setter") ||     
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-route-akamai") ||   
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-edge-cache-expiry") ||   
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-edge-cache-duration") ||   
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("link") ||   // link to metadata about the site
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-httpd") ||   // response header information and usage statistics.
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("transfer-encoding") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-timer") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-vcache") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("cache-control") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("connection") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-proxy-cache") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-response-time") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-cdn-rule") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("date") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("etag") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("age") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-cache") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("fastly-restarts") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("upgrade") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-cache") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("status") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("keep-alive") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("cf-cache-status") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("content-length") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("content-language") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("expires") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-runtime") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-rateLimit-reset") ||
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-ratelimit-limit") ||     
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("x-rateLimit-remaining") ||    
                        myWebHeaderCollection.GetKey(i).ToLower().Contains("last-modified")
                        )
                    {
                        continue;
                    }
                    else
                    {
                        
                        if (  // Cookie related: 
                            myWebHeaderCollection.GetKey(i).ToLower().Contains("cookie") ||
                            myWebHeaderCollection.GetKey(i).ToLower().Contains("p3p") ||  // Certain browsers require a P3P compact policy for cookies to be sent or received in some cases, including the situation involved in the SUL login check
                            myWebHeaderCollection.GetKey(i).ToLower().Contains("vary") ||
                            myWebHeaderCollection.GetKey(i).ToLower().Contains("alt-svc") ||  // alternate service - could be a backup server
                            myWebHeaderCollection.GetKey(i).ToLower().Contains("x-logged-in")  
                            )
                        {

                            Console.ForegroundColor = ConsoleColor.Green;

                            if (myWebHeaderCollection.GetKey(i).ToLower().Contains("vary") && !myWebHeaderCollection.Get(i).ToLower().Contains("cookie"))
                            {
                                Console.ForegroundColor = ConsoleColor.Gray;
                            } if (myWebHeaderCollection.GetKey(i).ToLower() == "set-cookie")
                            {
                                Console.WriteLine("\t" + myWebHeaderCollection.GetKey(i));
                                string[] values = myWebHeaderCollection.Get(i).Split(';');
                                for (int j = 0; j < values.Length; j++)
                                {
                                    if(j == 0)
                                    {   // Don't highlight the Cookie's value or try to process it
                                        Console.ForegroundColor = ConsoleColor.Gray;    
                                        Console.WriteLine("\t\t" + values[j].Trim());
                                    }
                                    else
                                    {
                                        Console.ForegroundColor = ConsoleColor.Green;
                                        Console.WriteLine("\t\t" + values[j].Trim());
                                        page.setCookieParam(values[j].Trim());
                                    }
                                        
                                }
                            }
                            else
                            {
                                Console.WriteLine("\t" + myWebHeaderCollection.GetKey(i) + " = " + myWebHeaderCollection.Get(i));
                            }

                            
                            Console.ForegroundColor = ConsoleColor.Gray;
                        }
                        else if ( // Security related: 
                          //myWebHeaderCollection.GetKey(i).ToLower().Contains("content-type") ||
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("x-frame-options") ||
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("strict-transport-security") ||
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("permissions-policy") ||
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("cross-origin-opener-policy") ||
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("cross-origin-resource-policy") ||
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("timing-allow-origin") ||
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("x-origin-time") ||
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("report-to") ||        // Whenever a user visits a page on your site, their browser sends JSON-formatted reports regarding anything that violates the content security policy to this URL
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("x-redis") ||
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("x-content-type-options") ||

                          // Access Control around the idea of Same Origin Policy (SOP).
                          // Headers that start with, "access-control" are sent back to the browser to tell it what it should* be doing and what it should* have access to across origins (aka sites)
                          // So these headers are designed to tell the browser how to access Cross Origin Resources (for Sharing) aka CORS so these are 'CORS' headers
                          myWebHeaderCollection.GetKey(i).ToLower().StartsWith("access-control") ||
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("access-control-allow-credentials") ||
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("access-control-allow-methods") ||
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("access-control-allow-headers") ||
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("access-control-allow-origin") ||  // Access-Control-Allow-Origin response header to tell the browser that the content of this page is accessible to certain origins. https://stackoverflow.com/questions/10636611/how-does-access-control-allow-origin-header-work
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("content-security-policy") ||
                          myWebHeaderCollection.GetKey(i).ToLower().Contains("origin"))
                        {  // Security related:
                            Console.ForegroundColor = ConsoleColor.DarkYellow;
                            if ( myWebHeaderCollection.GetKey(i).ToLower().Contains("content-security-policy") )
                            {   // print a new line for each of the values in content-security-policy
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.WriteLine("\t" + myWebHeaderCollection.GetKey(i));
                                string[] values = myWebHeaderCollection.Get(i).Split(';');
                                for(int j = 0; j < values.Length; j++)
                                {
                                    string policy = values[j].Trim();
                                    string[] policyArray = policy.Split(' ');
                                    string key = policyArray[0];
                                    Console.ForegroundColor = ConsoleColor.White;
                                    if (key.Contains("upgrade-insecure-requests"))
                                        Console.ForegroundColor = ConsoleColor.Cyan;
                                    if (key.Contains("block-all-mixed-content"))
                                        Console.ForegroundColor = ConsoleColor.Gray;    // Depecated
                                    
                                    Console.Write("\t\t" + key) ;

                                    // Break up and isolate the value componentns and highlight them if they are terrible security controls
                                    List<string> list = new List<string>(policyArray);
                                    list.RemoveAt(0);
                                    policyArray = list.ToArray();
                                    foreach (string param in policyArray)
                                    {
                                        string normalized = param.ToLower().Trim();
                                        if ( // Red Color dangerous CSP values
                                            normalized == "'unsafe-inline'" ||
                                            normalized == "'unsafe-eval'" ||
                                            normalized == "'strict-dynamic'" || 
                                            normalized == "*" || 
                                            normalized == "https:")
                                        {
                                            Console.ForegroundColor = ConsoleColor.Red;
                                            Console.Write(" " + param);
                                        }
                                        else
                                        {
                                            Console.ForegroundColor = ConsoleColor.Cyan;
                                            Console.Write(" " + param);
                                        }
                                    }
                                    Console.WriteLine();
                                    string value = string.Join(" ", policyArray);
                                    page.setCSPParam(key, value);

                                    Console.ForegroundColor = ConsoleColor.Gray;

                                    
                                }
                            } 
                            else
                            {   // print it yellow without formating
                                Console.WriteLine("\t" + myWebHeaderCollection.GetKey(i) + " = " + myWebHeaderCollection.Get(i));
                                page.processGenericSecurityHeader(myWebHeaderCollection.GetKey(i), myWebHeaderCollection.Get(i));
                            }
                            Console.ForegroundColor = ConsoleColor.Gray;
                        }
                        else  // Everything else
                        {
                            Console.WriteLine("\t" + myWebHeaderCollection.GetKey(i).ToLower() + " = " + myWebHeaderCollection.Get(i));
                        }

                        
                        Console.ForegroundColor = ConsoleColor.Gray;
                    }

                }

                int counter = 0;
                foreach (LinkItem link in LinkFinder.Find(html))
                {
                    string href = link.ToString();
                    //System.Console.WriteLine(href);
                    if (href != null)
                    {
                        if (href.Contains(".net") || href.Contains(".com") || href.Contains(".org"))
                        {
                            links.Enqueue(href);
                            counter++;
                        }
                    }
                }



                System.Console.Write("Security Description of ");
                Console.ForegroundColor = ConsoleColor.White;
                System.Console.WriteLine(site);

                System.Console.WriteLine(page);
                Console.ForegroundColor = ConsoleColor.Gray;
                System.Console.WriteLine("Done. Added "+ counter + " sites. Total is " + links.Count + " Press Enter for next");
                System.Console.ReadLine();
            } // end while loop



            return 0;
        }

        public static void ShuffleQueue<T>(this Queue<T> queue)
        {
            Random rng = new Random();
            var values = queue.ToArray();
            queue.Clear();
            foreach (var value in values.OrderBy(x => rng.Next()))
                queue.Enqueue(value);
        }

        public static void ShuffleStack<T>(this Stack<T> stack)
        {
            Random rng = new Random();
            var values = stack.ToArray();
            stack.Clear();
            foreach (var value in values.OrderBy(x => rng.Next()))
                stack.Push(value);
        }
    }
}
/*

Interesting:

Scrapping https://www.timeanddate.com/time/map/
        Via = 1.1 varnish
Scrapping https://www.theadvocate.com/baton_rouge/opinion/letters/
        x-loop = 1
        x-robots-tag = noarchive
        x-ua-compatible = IE=edge,chrome=1
        x-tncms = 1.61.5; app8; 0.7s; 8M
Scrapping https://www.usatoday.com/media/latest/videos/news/
    Feature-Policy = camera 'none';display-capture 'none';geolocation 'none';microphone 'none';payment 'none';usb 'none';xr-spatial-tracking 'none'
    Gannett-Cam-Experience-Id = control:8
Scrapping http://www.xinhuanet.com/english/index.htm
    EagleId
Scrapping https://www.nytimes.com/
    onion-location = https://www.nytimesn7cgmftshazwhfgzm37qxb44r64ytbb2dj3x62d2lljsciiyd.onion/
    X-API-Version = F-F-VI
    x-gdpr = 0
    x-api-version
Scrapping https://www.houstonchronicle.com/opinion/
        X-Gen-Mode = full
Scrapping https://postcalc.usps.com/
        x-ruleset-version = 1.3


What does the starter 'X-' mean?

 * */