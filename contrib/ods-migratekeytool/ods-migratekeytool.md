OpenDNSSEC HSM Migration tool tool
==================================

This tool can be used to migrate from one instance to another,
where both you migrate to a new OpenDNSSEC instance AND you
migrate to a new HSM instance without the ability to migrate
the keys to the new environment.  This requires a special kind
of DS roll-over where the public key material is being
transfered between environments but the private keys are not.

More details on this tool will follow in a blog post.
