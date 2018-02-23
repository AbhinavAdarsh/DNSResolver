# “dig” tool and a “DNSSEC” resolver

1. "Dig Tool" : Basically a iterative DNS Resolver that when provided with URL resolves it to provide IP address along with
    Query time, message size and other information. It supports A, MX and NS record types. File: mydig.py
   
2. "DNSSec Resolver : A DNS Resolver with DNSSec protocol added to it for intergrity of DNS. After each resolution, the
   integrity of the	DNS response is verified.Based on whether the provided URL supports DNSSec or not, three kinds of 
   output is povided:
   a. DNSSEC is configured and everything	is verified	(Output: verified IP Address)
   b. DNSSEC is not	enabled	(Output:	“DNSSEC	not	supported”)
   c. DNSSEC is	configured but	the	digital	signature could	NOT	be	verified  (Output: “DNSSec verification failed”)
   File: DNSSec.py
   
3. Comparison of performance of my "dig" tool with
   i. google's DNS resolver
   ii. local DNS resolver
   
   Performance measurements: Used top 25 websites from (http://www.alexa.com/topsites.) (10 times each)
   Cumulative Distribution Fucntion (CDF) for the comparison is plotted.
   File: CDF.png
   
Input format: python mydig.py <URL with or without www> <Record type 'A'/'MX'/NS'>
              python DNSSec.py <URL with or without www> <With or without Record type 'A'/'MX'/NS'>
              
