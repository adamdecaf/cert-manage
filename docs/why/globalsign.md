## GlobalSign Issues

#### Accidental cross-signing

GlobalSign accidently revoked an intermediate certificates in a policy error.

[Customer release](https://downloads.globalsign.com/acton/fs/blocks/showLandingPage/a/2674/p/p-008f/t/page/fm/0)

**Full Release** (This is a copy incase that link dies.)
> Dear Valued GlobalSign Customer,

> As most of you are aware, we are experiencing an internal process issue (details below) that is impacting your business. While we have identified the root-cause, we deeply apologize for the problems this is causing you and wanted to ensure you that we are actively resolving the issue.

> GlobalSign manages several root certificates and for compatibility and browser ubiquity reasons provides several cross-certificates between those roots to maximize the effectiveness across a variety of platforms.  As part of a planned exercise to remove some of those links, a cross-certificate linking two roots together was revoked.  CRL responses had been operational for 1 week, however an unexpected consequence of providing OCSP responses became apparent this morning, in that some browsers incorrectly inferred that the cross-signed root had revoked intermediates, which was not the case.

> GlobalSign has since removed the cross-certificate from the OCSP database and cleared all caches. However, the global nature of CDNs and effectiveness of caching continued to push some of those responses out as far as end users.  End users cannot always easily clear their caches, either through lack of knowledge or lack of permission.  New users (visitors) are not affected as they will now receive good responses.

> The problem will correct itself in 4 days as the cached responses expire, which we know is not ideal. However, in the meantime, GlobalSign will be providing an alternative issuing CA for customers to use instead, issued by a different root which was not affected by the cross that was revoked, but offering the same ubiquity and does not require to reissue the certificate itself.

> We are currently working on the detailed instructions to help you resolve the issue and will communicate those instruction to you shortly.

> Thank you for your patience.

> Lila Kee
> Chief Product Officer
> GMO GlobalSign

> US +1 603-570-7060 | UK +44 1622 766 766 | EU +32 16 89 1900
> www.globalsign.com/en
