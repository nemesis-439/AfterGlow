#!/usr/bin/awk -f
#**************************************************************************
#
# This file is in the public domain.
#
# For more information email LoranceStinson+csv@gmail.com.
# Or see http://lorance.freeshell.org/csv/
#
# Parse a CSV string into an array.
# The number of fields found is returned.
# In the event of an error a negative value is returned and csverr is set to
# the error. See below for the error values.
#
# Parameters:
# string  = The string to parse.
# csv     = The array to parse the fields into.
# sep     = The field separator character. Normally ,
# quote   = The string quote character. Normally "
# escape  = The quote escape character. Normally "
# newline = Handle embedded newlines. Provide either a newline or the
#           string to use in place of a newline. If left empty embedded
#           newlines cause an error.
# trim    = When true spaces around the separator are removed.
#           This affects parsing. Without this a space between the
#           separator and quote result in the quote being ignored.
#
# These variables are private:
# fields  = The number of fields found thus far.
# pos     = Where to pull a field from the string.
# strtrim = True when a string is found so we know to remove the quotes.
#
# Error conditions:
# -1  = Unable to read the next line.
# -2  = Missing end quote.
# -3  = Missing separator.
#
# DEBUG Information
# csverr = String with explain what is wrong.
#
# Notes:
# The code assumes that every field is preceded by a separator, even the
# first field. This makes the logic much simpler, but also requires a
# separator be prepended to the string before parsing.
#**************************************************************************
function parse_csv(string,csv,sep,quote,escape,newline,trim, fields,pos,strtrim) {
    # Make sure there is something to parse.
    if (length(string) == 0) return 0;
    string = sep string; # The code below assumes ,FIELD.
    fields = 0; # The number of fields found thus far.
    while (length(string) > 0) {
        # Remove spaces after the separator if requested.
        if (trim && substr(string, 2, 1) == " ") {
            if (length(string) == 1) return fields;
            string = substr(string, 2);
            continue;
        }
        strtrim = 0; # Used to trim quotes off strings.
        # Handle a quoted field.
        if (substr(string, 2, 1) == quote) {
            pos = 2;
            do {
                pos++
                if (pos != length(string) &&
                    substr(string, pos, 1) == escape &&
                    (substr(string, pos + 1, 1) == quote ||
                     substr(string, pos + 1, 1) == escape)) {
                    # Remove escaped quote characters.
                    string = substr(string, 1, pos - 1) substr(string, pos + 1);
                } else if (substr(string, pos, 1) == quote) {
                    # Found the end of the string.
                    strtrim = 1;
                } else if (newline && pos >= length(string)) {
                    # Handle embedded newlines if requested.
                    if (getline == -1) {
                        csverr = "Unable to read the next line.";
                        return -1;
                    }
                    string = string newline $0;
                }
            } while (pos < length(string) && strtrim == 0)
            if (strtrim == 0) {
                csverr = "Missing end quote.";
                return -2;
            }
        } else {
            # Handle an empty field.
            if (length(string) == 1 || substr(string, 2, 1) == sep) {
                csv[fields] = "";
                fields++;
                if (length(string) == 1)
                    return fields;
                string = substr(string, 2);
                continue;
            }
            # Search for a separator.
            pos = index(substr(string, 2), sep);
            # If there is no separator the rest of the string is a field.
            if (pos == 0) {
                csv[fields] = substr(string, 2);
                fields++;
                return fields;
            }
        }
        # Remove spaces after the separator if requested.
        if (trim && pos != length(string) && substr(string, pos + strtrim, 1) == " ") {
            trim = strtrim
            # Count the number fo spaces found.
            while (pos < length(string) && substr(string, pos + trim, 1) == " ") {
                trim++
            }
            # Remove them from the string.
            string = substr(string, 1, pos + strtrim - 1) substr(string,  pos + trim);
            # Adjust pos with the trimmed spaces if a quotes string was not found.
            if (!strtrim) {
                pos -= trim;
            }
        }
        # Make sure we are at the end of the string or there is a separator.
        if ((pos != length(string) && substr(string, pos + 1, 1) != sep)) {
            csverr = "Missing separator.";
            return -3;
        }
        # Gather the field.
        csv[fields] = substr(string, 2 + strtrim, pos - (1 + strtrim * 2));
        fields++;
        # Remove the field from the string for the next pass.
        string = substr(string, pos + 1);
    } # End of While
    return fields;
}

# Graph theory
# 2NODE Graph -> Source Node - Destination Node
# 3NODE Graph -> Source Node - Event Node - Destination Node

# Use case                              Source Node - Event Node - Destination Node
# Port scan (Ports)			             SourceIP     DestIP        DestPort
# Machine scan (IPs)                     SourceIP     NONE          DestIP
# Machine scan (IPs + SamePort)          SourceIP     DestPort      DestIP
# Finding machines for which certain traffic was blocked and for which other traffic was allowed through   SourceIP     Action     DestIP
# Which machines that access a specific service (destination port) and are they allowed to do so? DestPort   SourceIP      Action


# Prepare variables for convert column_name to number of column and reverse.
BEGIN {
  # col_mask="Received,Facility,Program,Host,Details";
  #For Afterglow - firewall
  #col_mask_string="Timestamp,Original timestamp,.dict.srcip,.dict.srcport,.dict.dstip,.dict.dstport,.dict.cee.action";
  #For Gource - firewall
  col_mask_string="Original timestamp,.dict.dev,.dict.connprotocol,.dict.srcip,.dict.srcport,.dict.dstip,.dict.dstport,.dict.cee.action";
  col_cnt=split(col_mask_string, col_mask, ",");
#  print col_cnt;
#  for (i=1; i<=col_cnt; i++)
#       { print i, col_m[i];}
#     print "---- BEGIN ---------------\n";
}


{
 num_fields = parse_csv($0, csv, ",", "\"", "\"", "\\n", 1);
 if (NR==1)
    {
     #num_fields = parse_csv($0, csv, ",", "\"", "\"", "\\n", 1);
     # Operate of header.
     # Prepare pair-value -> value of column_name is index and index is value.
     for (i=0; i<num_fields; i++)
       { col_name[csv[i]]=i; }
#     print "--------------------\n";
  
    } else {
       # Operate of body -> values.
       #num_fields = parse_csv($0, csv, ",", "\"", "\"", "\\n", 1);
       if (num_fields < 0) {
            printf "ERROR: %s (%d) -> %s\n", csverr, num_fields, $0;
       } else {
               for (i=1; i<col_cnt; i++)
                   { printf "%s,", csv[col_name[col_mask[i]]];}
               printf "%s\n", csv[col_name[col_mask[col_cnt]]];

              } #End of elseif (num_fields < 0)
    } #End of elseif  if (NR==1)
}
# ------- END -------



