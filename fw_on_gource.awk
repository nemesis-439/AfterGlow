BEGIN {
FS=",";
c["allow"]="FF0000";
c["block"]="00FF00";

}
{

print $1 "|" $4 "|M|" $2 "/" $3 "/" $6 "/" $7 "|" c[$8];
}