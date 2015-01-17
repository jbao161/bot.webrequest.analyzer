# bot.webrequest.analyzer
checks a web CLF log file against known bot agents and suspect IP addresses to estimate the percentage of traffic due to bots to a site

*** Usage:
in terminal or cmd, call 
  bot.analyzer log_file

optional flags:
  -ftype filetype_file
  -agent useragent_file
  -ip ipaddress_file
  
example:
  bot.analyzer example01.log -ftype request_types.txt -agent botlist.txt -ip ipbanlist.txt
  
*** Requirements:
  the ftype, agent, and ip files provided OR use your own
  
*** Output:
  generates a .report file listing the suspicious CLF log entries with a summary including the total page count, the number of suspicious requests, and the estimated percentage of traffic due to bots
  
*** What it does:
Scans a log file line by line and checks the following in sequence:
 1. Is the url request of a suspicious file type?
  (.htm, .html, .shtml, .xhtml, .asp, .aspx, .php, .pl, .cgi, .cfm, .do, .jsp)
  -> if yes, go to step 2

 2. is the User Agent on blacklist?
  -> if yes, report bot detection and skip step 3

 3. is IP Address is on blacklist?
  -> if yes, report bot detection
  a) when was the IP last seen?
  b) what is the likelihood it is bot

The sum requests of suspicious file types is the total page count.
The number of bot detections divided by the total page count gives a high estimate of the percentage of bot traffic.
The number of certain detections divided by the total page count gives a low estimate of the percentage of bot traffic.
The sum of the individual likelihoods of each detection divided by the total page count gives a best estimate of the percentage of bot traffic.

*** Sample output:
_ 49129 IP 37.58.100.142 1.0 2014-06-08 23:46:57.065 37.58.100.142 - - [27/Aug/2014:05:53:23 -0600] "GET /vendor/view.html?vendor_id=1821 HTTP/1.1" 301 178 "-" "Mozilla/5.0 (compatible; AhrefsBot/5.0; +http://ahrefs.com/robot/)"
_ 
_ 
_ Bot detection report
_ each line consists of the following space delimited data: "A B C D E F"
_ A: Line number at which the entry is found in log file
_ B: Detection type (IP/AGENT)
_ C: Matching text in the request
_ D: Likelihood of being a bot
_ E: most recent date seen
_ F: Complete CLF log entry of the suspect request
_ 
_ log file: example3.log
_ date/time: 2015.01.17.014127
_ 
_ total page count 184
_ number of detections 45
_ assuming all detections are actually bots, the percentage of bot traffic is 24.456522%
_ 
_ of the detections, 55.555556% are not certain to be bots. 100.000000% were identified by IP address and 0.000000% by _ user agent
_ if all uncertain detections are not bots, the percentage of bot traffic is 10.869565%
_ 
_ weighting the percentage by the individual probabilities of each uncertain detection,
_ the estimated percentage of bot traffic is 15.734647%
_ 
_ therefore, bot activity is from 10.869565% to 24.456522%, with a best estimate at 15.734647%
