cat keywords.txt | xargs -n 1 -I{} grep -Hnr "{}" --include={*.js,*.html} 2>/dev/null > loot
cat loot
