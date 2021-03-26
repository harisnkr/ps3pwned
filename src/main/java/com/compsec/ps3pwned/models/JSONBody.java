package com.compsec.ps3pwned.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;


@AllArgsConstructor
@NoArgsConstructor
@Data
public class JSONBody {
    String srn;
    String name;
    Credentials alice;
    List<Message> signedMessages;
}



