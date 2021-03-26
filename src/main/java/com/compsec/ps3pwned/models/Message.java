package com.compsec.ps3pwned.models;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class Message {
    String text;
    SignatureCoordinates signature;
}
