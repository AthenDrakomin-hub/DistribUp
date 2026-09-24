/**
 * RBAC 权限中间件
 * 支持: admin 管理员, user 普通用户, team_admin 团队管理员
 */

function checkPermission(requiredRole) {
  const roles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
  
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: '未登录，请先认证' });
    }

    try {
      const jwt = require('jsonwebtoken');
      const JWT_SECRET = process.env.JWT_SECRET || 'distribup_secret_key_change_in_production';
      const decoded = jwt.verify(token, JWT_SECRET);
      
      req.user = decoded;
      
      // 检查角色权限
      const userRole = decoded.role || 'user';
      const hasPermission = roles.includes(userRole);
      
      if (!hasPermission) {
        return res.status(403).json({ 
          error: '权限不足',
          required: roles,
          current: userRole
        });
      }
      
      next();
    } catch (err) {
      return res.status(401).json({ error: 'Token 无效或已过期' });
    }
  };
}

// 团队隔离中间件
function checkTeamOwnership() {
  return async (req, res, next) => {
    try {
      const db = require('./database');
      const { team_id } = req.params;
      
      if (!team_id) {
        return next(); // 非团队资源
      }
      
      const user = req.user;
      
      // Admin 可访问所有团队
      if (user.role === 'admin') {
        return next();
      }
      
      // 检查用户是否属于该团队
      const teamMember = await db.get(
        'SELECT id FROM users WHERE id = ? AND team_id = ?',
        [user.id, team_id]
      );
      
      if (!teamMember) {
        return res.status(403).json({ error: '无权访问该团队资源' });
      }
      
      next();
    } catch (err) {
      console.error('团队权限检查失败:', err);
      res.status(500).json({ error: '权限检查失败' });
    }
  };
}

// 资源所有者检查
function checkResourceOwner(resourceTable, idParam = 'id') {
  return async (req, res, next) => {
    try {
      const db = require('./database');
      const resourceId = req.params[idParam];
      const userId = req.user.id;
      
      const record = await db.get(
        `SELECT id, created_by, team_id FROM ${resourceTable} WHERE id = ?`,
        [resourceId]
      );
      
      if (!record) {
        return res.status(404).json({ error: '资源不存在' });
      }
      
      // Admin 可删除所有
      if (req.user.role === 'admin') {
        return next();
      }
      
      // 检查是否为所有者或同团队
      const isOwner = record.created_by === userId;
      const isTeamMember = await db.get(
        'SELECT id FROM users WHERE id = ? AND team_id = ?',
        [userId, record.team_id]
      );
      
      if (!isOwner && !isTeamMember) {
        return res.status(403).json({ error: '无权操作此资源' });
      }
      
      next();
    } catch (err) {
      console.error('资源所有权检查失败:', err);
      res.status(500).json({ error: '权限检查失败' });
    }
  };
}

module.exports = { checkPermission, checkTeamOwnership, checkResourceOwner };
