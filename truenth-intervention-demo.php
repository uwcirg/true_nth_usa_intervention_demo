<?php

/**
Pseudo code to illustrate server-side use of TrueNTH central services.
serverGet is an abstraction here; requires prep including obtaining a servie-level OAuth token.
PHP examples of that are here (though they're not very readable):
    https://github.com/uwcirg/opauth-truenth
    https://github.com/uwcirg/cakephp-opauth
*/
    define('CENTRAL_SERVICES_URL', 'https://truenth-demo.cirg.washington.edu/api/');

    foreach ($patientSpreadsheet as $patient){

        // create an account for the patient (NOTE: spec not finalized)
        $newAcctInfo = serverPOST(CENTRAL_SERVICES_URL . 'account');

        // assign demogaphic info
        serverPUT(CENTRAL_SERVICES_URL . 'demographics' . $newAcctInfo->user_id, 
                    '{"resourceType":"Patient",
                    "birthDate":"' . $patient->dob /* eg 1976-07-04 */ . '",
                    "gender":{"coding":[{"display":"' 
                        . $patient->gender /* eg male */ . '"}]},
                    "name":{"given":"' . $patient->fname /* eg John */ . 
                        '","family":"' . $patient->lname /* eg Doe */ . '"},
                    "telecom":[{"system":"email","value":"' 
                        . $patient->email /* eg johndoe@gmail.com */ . '"},
                    {"system":"phone","value":"' 
                        . $patient->phone /* eg 8885551212 */ . '"}]}');

        // assign the role 'patient'
        serverPUT(CENTRAL_SERVICES_URL . 'roles/' . $newAcctInfo->user_id, 
                    '[{"name":patient}]');

        // grant access to the sexual recovery intervention (NOTE: spec not finalized)
        // FIXME: interventions should be limited to calling this for their intervention only
        serverPUT(CENTRAL_SERVICES_URL . 'truenth/' . $newAcctInfo->user_id,
                    '[{"intervention":"sexual_recovery","status":"grant",' 
                    . '"card_html":"Click <a href="recovery.org">here</a> to learn more about sexual recovery"}]');

        // mail the patient a unique registration email
        mail($patient->email, "Please register for TrueNTH here: " 
                . $newAcctInfo->webkey_url);
    }

?>
