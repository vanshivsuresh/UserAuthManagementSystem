from rest_framework import permissions

class IsAdminUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'admin'

class IsRegularUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'user'