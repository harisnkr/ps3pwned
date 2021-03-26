package com.compsec.ps3pwned.models;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ECParameters {
    String name, p, a, b;
    KeyCoordinates g;
    String n;
}
