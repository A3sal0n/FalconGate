event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( meta$mime_type != "text/plain" && meta$mime_type != "image/jpeg" && meta$mime_type != "image/png" && meta$mime_type != "text/html" && meta$mime_type != "application/x-x509-ca-cert" && meta$mime_type != "application/x-x509-user-cert" && meta$mime_type != "application/ocsp-response" && meta$mime_type != "application/xml" )
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
    }