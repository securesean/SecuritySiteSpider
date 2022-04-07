using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace SecuritySiteSpider
{
    public static class Program
    {

        public static bool printDefaultFailures = true;
        private static bool shuffleFlag = false;

        // This is just a simple data class to contain the default security state
        // as dictated as the headers state. I'm basiclly doing this to codify my 
        // own knowledge. This is not meant for other people
        class SiteSecurityState
        {

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
                string sumString = "";  // This is dumb. I have no idea why I did it like this. Note: don't code while sick and tired

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
                        //else... idk I'm confused about this
                        //{
                        //    // "The browser will not leak the cookie over an http connection" AND... coming from another site will also work
                        //    sumString += "The cookie will only be sent back to the original site but NOT when a user clicks a link from another site to here (aka no Cross Site Requests, aka no CSRF)";
                        //}
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
                            sumString += "\n\t\t" + "The browser also might confuse some html or text for javascript";
                        }
                    }
                    else
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
                }
                else
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

                }
                else
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
                        if (embeddedList.Count == 0)
                        {
                            sumString += " from ANYWHERE";
                        }
                        else
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
                        {
                            Console.ForegroundColor = ConsoleColor.Gray;
                            Console.WriteLine("\t(Non-standard Cookie component)");
                            Console.ForegroundColor = ConsoleColor.Green;
                        }
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
                        if (printDefaultFailures)
                        {
                            Console.ForegroundColor = ConsoleColor.Gray;
                            Console.WriteLine("What is the default value of " + key.ToLower());
                            Console.ForegroundColor = ConsoleColor.DarkYellow;
                        }
                            
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
                if (value.ToLower().Contains("nosniff"))
                {
                    Xss_NoMimeSniffing = true;
                }
                else
                {
                    Console.WriteLine("\t\tError: x-content-type-options should only be able to have 'nosniff' and it has: " + value);
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
                        if (printDefaultFailures)
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
            string metaTagFailLog = "MetaTagFail.log";
            string htmlLogPath = "LastPage.html";
            List<string> visited = new List<string>();
            Queue<string> links = new Queue<string>();

            foreach(string arg in args)
            {
                if (arg.ToLower() == "-h" || arg.ToLower() == "--help")
                {
                    Console.WriteLine("Only supported arguments are URL's to start the spider and 'shuffle'");
                    return 0;
                }
                else if (arg.ToLower() == "-shuffle" || arg.ToLower() == "-randomize")
                {
                    shuffleFlag = true;
                }
                else
                {
                    if (arg.StartsWith("http://") || arg.StartsWith("https://"))
                        links.Enqueue(arg);
                    else
                    {
                        links.Enqueue("http://" + arg);
                        links.Enqueue("https://" + arg);
                    }
                }
            }

            links.Enqueue("https://www.nytimes.com/subscription/dg-cookie-policy/cookie-policy.html");
            links.Enqueue("https://www.nytimes.com/column/thomas-l-friedman");
            links.Enqueue("https://refdesk.com/");
            links.Enqueue("https://sdb.tools/");
            links.Enqueue("https://www.openstreetmap.org/?mlat=22.4449&amp;mlon=114.0263#map=15/22.4449/114.0263");
            links.Enqueue("https://www.mapquest.com/search/results?query=Gas");
            links.Enqueue("https://www.washingtonpost.com/");
            links.Enqueue("https://medlineplus.gov/");
            links.Enqueue("https://fun.chicagotribune.com/game/tca-jumble-daily");
            links.Enqueue("https://www.startribune.com/local/");
            links.Enqueue("http://www.mozilla.com/");
            links.Enqueue("https://www.pinterest.com");
            links.Enqueue("https://duckduckgo.com/");
            links.Enqueue("http://www.usatoday.com/sports/fantasy/football/");


            var securityList = new List<string>
{
    "x-frame-options",
    "strict-transport-security",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "timing-allow-origin",
    "x-origin-time",
    "report-to",        // Whenever a user visits a page on your site, their browser sends JSON-formatted reports regarding anything that violates the content security policy to this URL
    "x-redis",
    "x-content-type-options",

    // Access Control around the idea of Same Origin Policy (SOP).
    // Headers that start with, "access-control" are sent back to the browser to tell it what it should* be doing and what it should* have access to across origins (aka sites)
    // So these headers are designed to tell the browser how to access Cross Origin Resources (for Sharing) aka CORS so these are 'CORS' headers
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-allow-origin",  // Access-Control-Allow-Origin response header to tell the browser that the content of this page is accessible to certain origins. https://stackoverflow.com/questions/10636611/how-does-access-control-allow-origin-header-work
    "content-security-policy",
    "content-security-policy-report-only",
    "origin"

};

            var doNotPrintList = new List<string>
{
    "server",           // This might be fun 
    "x-client-ip",           // This might be fun 
    "x-powered-by",     // this might be fun
    "x-content-powered-by",     // this might be fun
    "x-served-by",     // this might be fun
    "served-by",     // this might be fun
    "x-servedbyhost",     // this might be fun - ::ffff:127.0.0.1
    "x-hosted-by",     // this might be fun to map
    "x-bbackend",     // this might be fun
    "x-backend",     // this might be fun
    "x-backend-server",     // this might be fun
    "x-datacenter",     // this might be fun
    "x-url",
    "x-host",
    "x-pbs-appsvrip",     // Bug: leaking internal IP info found on https://www.pbs.org/newshour/
    "x-pbs-",

    // Info about me (aka creepy)
    "x-dbg-gt",
    "x-true-client-ip",     

    // Proxy Related
    "x-forwarded-for",     // this might be fun
    "via",     // this might be fun

    // This might change the sites response format
    "vary",
    "x-ua-compatible",     

    // AWS
    "x-amz-cf-pop",
    "x-amz-cf-id",
    "x-amz-version-id",
    "x-amz-id-2",
    "x-amz-request-id",
    "x-amz-meta-uncompressed-size",   

    // Fastly
    "fastly-original-body-size",      

    // Security related but don't really matter
    "expect-ct",  // Cert transparency

    // CMS's
    "x-drupal-cache",  // Cert transparency
    "wpx",   // I think it's a wordpress site

    // Interesting
    "nel",   // Network Error Logging (404's and such)
    "accept-ranges",   // resume downloads from a certain byte offset

    "x-origin-time",
    "origin-trial",     // washingtonpost.com
    "x-xss-protection",     // this is on the ignore list because it's been retired by modern browsers
    "x-permitted-cross-domain-policies",  // used to permit cross-domain requests from Flash and PDF documents
    "x-download-options",     // just an IE-8 thing
    "referrer-policy",        // just a privacy thing https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy 
    "content-type",
    "akamai-grn",
    "x-cdn",
    "x-route",
    "x-origin-cache",
    "x-varnish",
    "pragma",
    "x-gt-setter",
    "x-route-akamai",
    "x-edge-cache-expiry",
    "x-edge-cache-duration",
    "link",   // link to metadata about the site
    "x-httpd",   // response header information and usage statistics.
    "transfer-encoding",
    "x-timer",
    "x-vcache",
    "cache-control",
    "connection",
    "x-proxy-cache",
    "x-response-time",
    "x-cdn-rule",
    "date",
    "etag",
    "age",
    "x-cache",
    "fastly-restarts",
    "upgrade",
    "x-cache",
    "status",
    "keep-alive",
    "cf-cache-status",
    "content-length",
    "content-language",
    "expires",
    "x-runtime",
    "x-rateLimit-reset",
    "x-ratelimit-limit",
    "x-rateLimit-remaining",
    "last-modified",


    // Meta tags that I don't care much about
};

            while (links.Count > 0)
            {
                if(shuffleFlag)
                    ShuffleQueue(links); 
                string site = links.Dequeue();
                if (visited.Contains(site))
                {
                    continue;
                }
                System.Console.WriteLine("Scrapping server headers and meta tags from " + site);

                WebClient web = new WebClient();
                string html = "";
                try
                {
                    html = web.DownloadString(site);
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    System.Console.WriteLine("Error: " + ex.Message);
                    Console.ForegroundColor = ConsoleColor.Gray;
                    continue;
                }
                visited.Add(site);
                writeToFile(html, htmlLogPath);

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
                // I might need to account for single quotes. See MetaTagFail.log. https://regex101.com/ is REALLY useful
                Regex allMetatags = new Regex("<meta.*name.*=\"(.*)\".*content.*=\"(.*)\">", RegexOptions.Compiled | RegexOptions.IgnoreCase);
                // Typical tags: <meta http-equiv="x-ua-compatible" content="IE=edge,chrome=1" />
                Regex securityMetaTags = new Regex("meta.*http-equiv.*=\"(.*)\".*content.*=\"(.*)\".*>", RegexOptions.Compiled | RegexOptions.IgnoreCase);
                // Tags without content: <meta content="on" http-equiv="x-dns-prefetch-control"/> 
                Regex securityNoContentMetaTags = new Regex("meta.*http-equiv.*=\"(.*)\".*>", RegexOptions.Compiled | RegexOptions.IgnoreCase);
                foreach (string line in html.Split('\n'))
                {
                    foreach (string tag in line.Split('<'))
                    {
                        bool metaTagFlag = false;
                        if (tag.Contains("http-equiv"))
                        {
                            metaTagFlag = true;
                            //Console.WriteLine("Should Catch: {0}", line.Trim());
                        }

                        MatchCollection matches = securityMetaTags.Matches(tag);
                        foreach (Match match in matches)
                        {
                            GroupCollection groups = match.Groups;
                            string key = groups[1].ToString();
                            string value = groups[2].ToString();
                            pageAttributesOrignial.Add(Tuple.Create(key, value));
                            pageAttributes.Add(Tuple.Create(key.ToLower(), value.ToLower()));
                            metaTagFlag = false;
                            if (key.ToLower().Contains("content-security"))
                            {
                                Console.WriteLine("\tFound CSP in meta tag: '{0}' = '{1}'", key, value);
                            }
                        }
                        if (metaTagFlag && !tag.StartsWith("!--"))
                        {
                            // Try again with a more general, no content regex:
                            matches = securityNoContentMetaTags.Matches(tag);
                            foreach (Match match in matches)
                            {
                                GroupCollection groups = match.Groups;
                                string key = groups[1].ToString();
                                string value = "";
                                pageAttributesOrignial.Add(Tuple.Create(key, value));
                                pageAttributes.Add(Tuple.Create(key.ToLower(), value.ToLower()));
                                metaTagFlag = false;
                            }

                            // If I still fail to scrape the meta tag, log it and move on
                            if (metaTagFlag)
                            {
                                string message = String.Format("RegEx did not this possible meta tag from site {0}: {1} ", site, line.Trim());
                                writeToFile(message, metaTagFailLog);
                            }

                           

                        }
                    }
                }


                SiteSecurityState page = new SiteSecurityState();



                foreach ((string key, string value) in pageAttributes)
                {
                    if (doNotPrintList.Contains(key))
                    {
                        continue;
                    }
                    else if (key.Contains("cookie"))
                    {   // Cookie Security
                        Console.ForegroundColor = ConsoleColor.Green;

                        if (key.Contains("vary") && !key.Contains("cookie"))
                        {
                            Console.ForegroundColor = ConsoleColor.Gray;
                        }
                        if (key == "set-cookie")
                        {
                            Console.WriteLine("\t" + key);
                            string[] values = value.Split(';');
                            for (int j = 0; j < values.Length; j++)
                            {
                                if (j == 0)
                                {   // Don't highlight the Cookie's value or try to process it
                                    Console.ForegroundColor = ConsoleColor.Gray;
                                    Console.WriteLine("\t\t" + values[j].Trim());
                                }
                                else
                                {
                                    Console.ForegroundColor = ConsoleColor.Green;
                                    Console.Write("\t\t" + values[j].Trim());
                                    page.setCookieParam(values[j].Trim());
                                    Console.WriteLine();
                                }

                            }


                            Console.ForegroundColor = ConsoleColor.Gray;
                        }
                        else
                        {
                            Console.WriteLine("\t" + key + " = " + value);
                        }
                    }// end if cookie 
                    else if (key == "http-equiv")
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("\t\t" + value);
                        Console.ForegroundColor = ConsoleColor.Gray;
                    }
                    else if (securityList.Contains(key))
                    {
                        Console.ForegroundColor = ConsoleColor.DarkYellow;
                        if (key.StartsWith("content-security-policy"))
                        {   // print a new line for each of the values in content-security-policy
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine("\t" + key);
                            string[] values = value.Split(';');
                            for (int j = 0; j < values.Length; j++)
                            {
                                string policy = values[j].Trim();
                                string[] policyArray = policy.Split(' ');
                                string cspKey = policyArray[0];
                                Console.ForegroundColor = ConsoleColor.White;
                                if (cspKey.Contains("upgrade-insecure-requests"))
                                    Console.ForegroundColor = ConsoleColor.Cyan;
                                if (cspKey.Contains("block-all-mixed-content"))
                                    Console.ForegroundColor = ConsoleColor.Gray;    // Depecated

                                Console.Write("\t\t" + cspKey);

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
                                string cspValue = string.Join(" ", policyArray);
                                page.setCSPParam(cspKey, cspValue);

                                Console.ForegroundColor = ConsoleColor.Gray;
                            }
                        }
                        else
                        {   // print it yellow without formating
                            Console.WriteLine("\t" + key + " = " + value);
                            page.processGenericSecurityHeader(key, value);
                        }
                        Console.ForegroundColor = ConsoleColor.Gray;
                    }
                    else // just print if nothing else
                    {
                        Console.ForegroundColor = ConsoleColor.Gray;
                        Console.WriteLine("\t{0} - {1}", key, value);

                    }
                } // end new/better for loop



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
                System.Console.WriteLine("Done. Added {0} sites. Total is {1}. Press Enter for next site", counter, links.Count);
                System.Console.ReadLine();
            } // end while loop



            return 0;
        }

        private static void writeToFile(string message, string path = @"GeneralRunLog.log")
        {
            // This text is added only once to the file.
            if (!File.Exists(path))
            {
                // Create a file to write to.
                using (StreamWriter sw = File.CreateText(path))
                {
                    sw.WriteLine(message);
                }
            }

            // This text is always added, making the file longer over time
            // if it is not deleted.
            using (StreamWriter sw = File.AppendText(path))
            {
                sw.WriteLine(message);
            }


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
