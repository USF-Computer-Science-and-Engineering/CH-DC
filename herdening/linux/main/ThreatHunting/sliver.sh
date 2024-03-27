
mapfile -d $'\0' files < <(sudo find / -type f -executable -size +1M -print0 2>/dev/null)

for i in "${files[@]}";
do 
    if [[ $(strings $i 2>/dev/null | grep 'sliver' 2>/dev/null) ]]; then   
        echo "Detected Potential Sliver Binary : $i"
    else
        continue
    fi
done