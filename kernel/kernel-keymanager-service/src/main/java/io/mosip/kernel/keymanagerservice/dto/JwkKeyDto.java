package io.mosip.kernel.keymanagerservice.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwkKeyDto {
    private String kty;
    private String kid;
    private String alg;
    private String crv;
    private String x;
    private List<String> x5c;
    private String y;

} 