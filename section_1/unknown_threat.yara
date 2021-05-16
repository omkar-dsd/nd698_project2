rule darklord_detector {
        meta:
                Author = "@omkar"
                Description = "This Rule Detects the Dark Lord Malware"
        strings:
                $drklrd = "darkl0rd.com"
        condition:
                $drklrd

}
