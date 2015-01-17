// <author>Jonathan Bao</author>
// <email>jbao161@gmail.com</email>
// <date>2015.01.17</date>
// <summary>checks a web CLF log file against known bot agents and suspect IP addresses to estimate the percentage of traffic due to bots to a site</summary>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>

// Objectives:
// 1. Count the number of requests
// 2. Estimate the percentage of bot traffic

// input:
// log file
// list of suspect file types in url request
// list of known bot user agent names
// list of suspect IP addresses
//
// output: list the suspect requests, report the percentage of suspect

// Analyzer tasks:
// 1. Is the url request of a suspicious file type?
//  a) .htm, .html, .shtml, .xhtml, .asp, .aspx, .php, .pl, .cgi, .cfm, .do, .jsp
//  b) "/(pretty URLs)" ???what does that mean???
// 2. is the User Agent on blacklist?
//  *****(if so, skip the IP check)*****
// 3. is IP Address is on blacklist?
//  a) when was bot last seen?
//  b) what is the likelihood it is bot
//    i) confidence factor in the final percentage of suspect bots

// set toggles to zero and the check will be skipped!
int ip_search_toggle = 1;
int agent_search_toggle = 1;

void test01()
{
    int i,j,k;

    char read_buffer[4096];

    char* log_filepath = "../example/example1.log";
    FILE* log_file = fopen(log_filepath,"r");
    char* filetype_filepath = "../lib/ftype";
    FILE* filetype_file;
    char* agent_filepath = "../lib/agent";
    FILE* agent_file;
    char* ip_filepath = "../lib/ip";
    FILE* ip_file;

    // current date/time in YYYY.MM.DD.TTTTTT format
    time_t sys_time;
    struct tm *sys_time_struct;
    time(&sys_time);
    sys_time_struct = localtime(&sys_time);
    char date_time[64];
    strftime(date_time, sizeof(date_time), "%Y.%m.%d.%H%M%S", sys_time_struct);
    //printf("%s\n",date_time);

    char foundbots_filepath [ FILENAME_MAX ];
    snprintf(foundbots_filepath, FILENAME_MAX, "../out/%s.report", date_time);
    FILE* foundbots_file;

    char ip_address[50];
    char user_agent[1024];
    char request[1024];

    // *** read into memory the list of file extensions we need to look at ***
    filetype_file = fopen(filetype_filepath,"r");
    int fext_length = 50;
    int num_filetypes = 0;
    int read_char, final_char = EOF;
    // count number of file extensions
    while ((read_char = fgetc(filetype_file)) != EOF)
    {
        if (read_char == '\n')
            num_filetypes++;
        final_char = read_char;
    }
    if (final_char != EOF && final_char != '\n')
        num_filetypes++;
    fclose(filetype_file);
    // read in the extension names
    filetype_file = fopen(filetype_filepath,"r");
    char** filetypes =  calloc(num_filetypes, sizeof(char*));
    for (i = 0; i < num_filetypes; i++)
    {
        char buff[50];
        filetypes[i] = calloc(fext_length,sizeof(char)+1);
        fgets(read_buffer, sizeof(read_buffer),filetype_file);
        sscanf(read_buffer, "%s", filetypes[i]);
    }
    fclose(filetype_file);

    // *** scan the log file ***
    int pagecount = 0;
    int bot_count = 0;
    int botagent_count = 0;
    int botip_count = 0;
    double likelihood;
    double sum_likelihood = 0;
    int sum_certain = 0;
    char* todouble_error;

    char* detected_type;
    char* detected_entry;
    char detected_lastseen[256];
    char detected_likelihood[256];
    char* agent_st = "AGENT";
    char* ip_st = "IP";
    char* na_st = "N/A";

    int num_current_line = 0;
    char current_line[4096];
    while (fgets(read_buffer, sizeof(read_buffer),log_file))
    {
        // stores the request number and the request
        // if it is a bot, the information will be saved to file
        num_current_line++;
        strcpy(current_line, read_buffer);

        // parse the Combined Log Format entry
        sscanf(read_buffer,
               // (add length qualifier like %256s if buffer overflow)
               "%s" // ip address
               "%*s %*s %*s %*s" // remote host, username, date/time, GMT offset
               " \"%[^\"]\"" // request in quotations
               "%*s %*s" // request status, size of transmition
               " \"%*[^\"]\"" // referrer URL in quotations
               " \"%[^\"]\"" // user agent in quotations
               , ip_address, request, user_agent);
        // printf("%s\n",read_buffer);
        // printf("%s \n%s \n%s \n\n\n", ip_address,request,user_agent);

        // ** 1. check the request type **
        int bool_scanrequest = -1;
        char requested_url[256];
        // the request is made of three parts: the action (GET), the url, and the protocol
        // we are interested in the url (second space delimited string)
        // however, we strip the url of any "?" modifier in case of.php extensions
        sscanf(request, "%*s %[^? ] %*s", requested_url);
        size_t len_requested_url = strlen(requested_url);
        for (i=0; i < num_filetypes; i++)
        {
            size_t len_file_extention = strlen(filetypes[i]);
            if (strcmp(requested_url + len_requested_url - len_file_extention, filetypes[i]) == 0)
            {
                // if url matches a predefined file extension, flag it for bot check and add to page count
                bool_scanrequest = 1;
                pagecount++;
                //printf("i found the extension %s\n",filetypes[i]);
            }
        }
        printf("%s\n", request);
        switch(bool_scanrequest)
        {
        case -1: // request is not a suspicious file type
            goto nobot_detected;
        case 1:
            if (agent_search_toggle ==0) goto ip_search;
            // ** 2. check the user agent **
            agent_file = fopen(agent_filepath,"r");
            while (fgets(read_buffer, sizeof(read_buffer),agent_file))
            {
                // if the user agent field is empty, assume it is <?not a bot?>
                if (strcmp("-", user_agent) == 0) goto nobot_detected;
                // does not seem necessary to exact match each user agent entry separately
                // if agent substring is found anywhere in the user agents file
                // it is considered a match. for example, an agent "user-agent" would give false positive
                if (strstr(read_buffer, user_agent) != NULL)
                {
                    botagent_count ++;
                    detected_type = agent_st;
                    detected_entry = user_agent;
                    strcpy(detected_likelihood, "1.0") ;
                    likelihood = 1.0;
                    strcpy(detected_lastseen, na_st);
                    goto bot_detected;
                }
            }
            fclose(agent_file);

ip_search:
            if (ip_search_toggle ==0) goto nobot_detected;
            // ** 3. check the ip address **
            ip_file = fopen(ip_filepath, "r");
            while (fgets(read_buffer, sizeof(read_buffer),ip_file))
            {
                if ( strstr(read_buffer, ip_address) != NULL)
                {
                    botip_count ++;
                    detected_type = ip_st;
                    detected_entry = ip_address;
                    sscanf(read_buffer,
                           "%*[^\x1f]\x1f" // ip address, followed by unit separator
                           "%[^\x1f]\x1f" // last seen date time, followed by unit separator
                           "%[^\x1e]\x1e" // probability of being a bot, followed by group separator
                           , detected_lastseen, detected_likelihood);
                    likelihood = strtod(detected_likelihood, &todouble_error);
                    printf("likelihood: %f\n",detected_likelihood);
                    //printf("~~~~~~~~~~~~~IP FOUND\n");
                    //printf("%s", read_buffer);
                    printf("%s | %s\n", detected_lastseen, detected_likelihood);
                    goto bot_detected;
                }
            }
            fclose(ip_file);
            goto nobot_detected;
            {
bot_detected:
                bot_count ++;
                sum_likelihood += likelihood;
                sum_certain += likelihood/1;
                // write to file the # of the entry followed by the entry
                foundbots_file = fopen(foundbots_filepath,"ab");
                fprintf (foundbots_file,
                         "%i %s %s "
                         "%s %s "
                         "%s"
                         , num_current_line, detected_type, detected_entry
                         , detected_likelihood, detected_lastseen
                         , current_line);
                fclose(foundbots_file);
            }
nobot_detected:
            {
                // do nothing
            }
        }
    }
    fclose(log_file);

    // *** save results to report file ***
    double hi_per_bottraffic = 100*bot_count/(double)pagecount;
    double per_ipdetect = 100*botip_count/(double)bot_count;
    double per_agentdetect = 100*botagent_count/(double)bot_count;

    double weighted_per_bottraffic = 100*sum_likelihood/(double)pagecount;
    double per_certaindetect = 100*sum_certain/(double)bot_count;
    double per_uncertaindetect = 100 - per_certaindetect;
    double low_per_bottraffic = 100*sum_certain/(double)pagecount;

    foundbots_file = fopen(foundbots_filepath,"ab");
    fprintf(foundbots_file,"\n\n"
            "Bot detection report\n"
            "each line consists of the following space delimited data: \"A B C D E F\"\n"
            "A: Line number at which the entry is found in log file\n"
            "B: Detection type (IP/AGENT)\n"
            "C: Matching text in the request\n"
            "D: Likelihood of being a bot\n"
            "E: most recent date seen\n"
            "F: Complete CLF log entry of the suspect request\n"
            "\n"
            "log file: %s\n"
            "date/time: %s\n"
            , log_filepath, date_time);
    fprintf(foundbots_file,"\n"
            "total page count %i\n"
            "number of detections %i\n"
            "assuming all detections are actually bots, the percentage of bot traffic is %f%%\n"
            , pagecount, bot_count, hi_per_bottraffic);
    fprintf(foundbots_file,"\n"
            "of the detections, %f%% are not certain to be bots. %f%% were identified by IP address and %f%% by user agent\n"
            "if all uncertain detections are not bots, the percentage of bot traffic is %f%%\n"
            "\n"
            "weighting the percentage by the individual probabilities of each uncertain detection,\n"
            "the likelihood percentage of bot traffic is %f%%\n"
            , per_uncertaindetect, per_ipdetect, per_agentdetect
            , low_per_bottraffic
            , weighted_per_bottraffic);
    fprintf(foundbots_file,"\n"
            "therefore, bot activity is from %f%% to %f%%, with a best estimate at %f%%\n"
            , low_per_bottraffic, hi_per_bottraffic, weighted_per_bottraffic);
    fclose(foundbots_file);

}

main (int arc, char **argv )
{
    test01();
    return 0;
}
