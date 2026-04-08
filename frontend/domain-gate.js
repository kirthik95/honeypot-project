(function () {
    var currentLocation = window.location;
    var currentHost = currentLocation.hostname;
    var firebaseSuffix = ".firebaseapp.com";

    if (!currentHost.endsWith(firebaseSuffix)) {
        return;
    }

    var preferredHost = currentHost.slice(0, -firebaseSuffix.length) + ".web.app";
    var canonicalUrl = currentLocation.protocol + "//" + preferredHost + currentLocation.pathname + currentLocation.search;

    try {
        var canonicalLink = document.querySelector('link[rel="canonical"]');

        if (!canonicalLink) {
            canonicalLink = document.createElement("link");
            canonicalLink.rel = "canonical";
            document.head.appendChild(canonicalLink);
        }

        canonicalLink.href = canonicalUrl;
    } catch (error) {
        // Ignore head mutation issues and continue with the redirect.
    }

    window.location.replace(canonicalUrl + currentLocation.hash);
})();
