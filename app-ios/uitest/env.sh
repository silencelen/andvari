# shellcheck shell=bash
# Shared by the UI-test scripts and the workflow. Sourced, not run.
#
# Hosts, and why:
#   127.0.0.1                the vault server. The app dials plain http only to this literal address
#                            (IOS_CLEARTEXT_EXEMPT_HOSTS); "localhost" is refused by design, so the tests must not use it.
#   site.andvari-uitest.test the test site over https, as real sites are. A hosts-file name for loopback, with its own
#                            registrable domain (andvari-uitest.test) so the eTLD+1 matching rule is the one exercised,
#                            and a certificate from a CA made in the job and trusted only by the job's simulator.
#   plainhttp-uitest.test    the same pages over plain http, under ANOTHER registrable domain, for the rule that an
#                            http page is only offered a login saved as http.
#   pay.andvari-uitest.test  the test site's stand-in payment provider (pages under /pay/), the one origin a card is
#                            filled into here (owner decision 2026-11-14: a card goes only to a payment provider's
#                            card form). Only the UI-test build of the Safari extension lists it (UITEST=1,
#                            extension/build.mjs); ios-unsigned.yml checks that the release bundle names no test domain.
# Neither site name is "localhost" or an IP address: the matcher treats IP literals as exact-only and browsers treat
# localhost as a special secure context, and neither is what a person's logins look like.
export UITEST_SERVER_PORT=8087
export UITEST_SERVER_ORIGIN="http://127.0.0.1:${UITEST_SERVER_PORT}"
export UITEST_SITE_HOST="site.andvari-uitest.test"
export UITEST_SITE_PORT=8443
export UITEST_SITE_ORIGIN="https://${UITEST_SITE_HOST}:${UITEST_SITE_PORT}"
# A second https site under another registrable domain, same pages and port, for a fill that crosses sites.
export UITEST_OTHER_HOST="other-uitest.test"
export UITEST_OTHER_ORIGIN="https://${UITEST_OTHER_HOST}:${UITEST_SITE_PORT}"
# The stand-in payment provider: the same pages and port under its own name, which the site's certificate carries too.
export UITEST_PROVIDER_HOST="pay.andvari-uitest.test"
export UITEST_PROVIDER_ORIGIN="https://${UITEST_PROVIDER_HOST}:${UITEST_SITE_PORT}"
export UITEST_HTTP_HOST="plainhttp-uitest.test"
export UITEST_HTTP_PORT=8081
export UITEST_HTTP_ORIGIN="http://${UITEST_HTTP_HOST}:${UITEST_HTTP_PORT}"
# A throwaway account on a throwaway loopback server: these are test fixtures, not secrets.
export UITEST_EMAIL="uitest@andvari-uitest.test"
export UITEST_PASSWORD="correct horse battery staple uitest 1"
