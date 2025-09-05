package com.sidar.demo2.controller;

import com.sidar.demo2.dto.UserDto;
import com.sidar.demo2.model.Role;
import com.sidar.demo2.service.UserService;
import com.sidar.demo2.service.BookService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')") // Minimum ADMIN yetkisi gerekli
@RequiredArgsConstructor
public class AdminController {

    private final UserService userService;
    private final BookService bookService;

    // Kullanıcı rolü değiştir (Sadece SUPER_ADMIN yapabilir)
    @PutMapping("/users/{userId}/role")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Map<String, String>> changeUserRole(
            @PathVariable Long userId,
            @RequestParam Role newRole) {

        userService.changeUserRole(userId, newRole);
        return ResponseEntity.ok(Map.of(
                "message", "User role updated successfully",
                "newRole", newRole.name()
        ));
    }

    // Tüm kullanıcıları listele
    @GetMapping("/users")
    public Page<UserDto> getAllUsers(Pageable pageable) {
        return userService.getAllUsers(pageable);
    }

    // Role göre kullanıcıları getir
    @GetMapping("/users/by-role")
    public Page<UserDto> getUsersByRole(@RequestParam Role role, Pageable pageable) {
        return userService.getUsersByRole(role, pageable);
    }

    // Kullanıcı durumunu değiştir (aktif/pasif)
    @PutMapping("/users/{userId}/status")
    public ResponseEntity<Map<String, String>> changeUserStatus(
            @PathVariable Long userId,
            @RequestParam boolean active) {

        userService.changeUserStatus(userId, active);
        return ResponseEntity.ok(Map.of(
                "message", "User status updated successfully",
                "status", active ? "ACTIVE" : "INACTIVE"
        ));
    }

    // Kullanıcı arama
    @GetMapping("/users/search")
    public ResponseEntity<UserDto> searchUser(@RequestParam String query) {
        try {
            // Email ile ara
            if (query.contains("@")) {
                return ResponseEntity.ok(userService.findByEmail(query));
            }
            // Username ile ara
            return ResponseEntity.ok(userService.findByUsername(query));
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    // Sistem istatistikleri
    @GetMapping("/stats")
    public Map<String, Object> getSystemStats() {
        return Map.of(
                "totalUsers", userService.getTotalUserCount(),
                "activeUsers", userService.getActiveUserCount(),
                "totalBooks", bookService.getTotalBookCount(),
                "registrationsToday", userService.getTodayRegistrations()
        );
    }

    // Hızlı admin promosyonu
    @PutMapping("/promote-to-admin/{userId}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Map<String, String>> promoteToAdmin(@PathVariable Long userId) {
        userService.changeUserRole(userId, Role.ADMIN);
        return ResponseEntity.ok(Map.of(
                "message", "User promoted to ADMIN successfully"
        ));
    }

    // Bulk işlemler
    @PostMapping("/users/bulk-deactivate")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Map<String, String>> bulkDeactivate(@RequestBody java.util.List<Long> userIds) {
        userService.deactivateMultipleUsers(userIds);
        return ResponseEntity.ok(Map.of(
                "message", userIds.size() + " users deactivated successfully"
        ));
    }
}