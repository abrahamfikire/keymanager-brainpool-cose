package io.mosip.kernel.keymanagerservice.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwksResponseDto {
    private List<JwkKeyDto> keys;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class JwkKeyDto {
        private String alg;
        private String crv;
        private String kid;
        private String kty;
        private String x;
        private String y;
        private List<String> x5c;
    }
} 