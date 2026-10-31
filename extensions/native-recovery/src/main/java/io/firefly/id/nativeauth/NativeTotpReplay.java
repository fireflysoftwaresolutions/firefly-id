package io.firefly.id.nativeauth;

import jakarta.persistence.*;
@Entity @Table(name="ff_native_totp_replay")
public class NativeTotpReplay {
    @Id @Column(length=128) public String id;
    @Column(name="expires_at") public long expiresAt;
}
