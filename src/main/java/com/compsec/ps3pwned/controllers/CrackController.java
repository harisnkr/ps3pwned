package com.compsec.ps3pwned.controllers;

import com.compsec.ps3pwned.services.CrackLogic;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CrackController {

    @Autowired
    private CrackLogic crackLogic;

    @GetMapping("/{srn}")
    public String getAnswer(@PathVariable("srn") String srn) throws Exception {
        return crackLogic.doAll(srn);
    }

}