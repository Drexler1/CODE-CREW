# ═══════════════════════════════════════════════════════════════
# Books & Blooms Café — New Inventory API Routes
# Add these routes to app.py (alongside the existing routes)
# ═══════════════════════════════════════════════════════════════
#
# These routes power the redesigned inventory.html:
#   GET    /api/inv_items            - list all inventory items
#   POST   /api/inv_items            - create item
#   PUT    /api/inv_items/<id>       - update item
#   DELETE /api/inv_items/<id>       - soft-delete item
#   POST   /api/inv_items/adjust     - manual stock adjustment
#   GET    /api/inv_items/log        - recent deduction log
#
# Auto-deduction on checkout:
#   Modify the existing /api/pos/checkout route to call
#   _deduct_cups_for_sale(transaction_id, items) after committing
#   the transaction.
# ═══════════════════════════════════════════════════════════════


# ── Helpers ───────────────────────────────────────────────────

CUP_UNITS = {'8oz', '12oz', '16oz'}   # units that auto-deduct from inv_items

def _log_inv_change(cur, item_id, item_name, unit, delta, stock_after,
                    source='manual', transaction_id=None, note=None, created_by=None):
    """Insert a row into inv_log."""
    cur.execute("""
        INSERT INTO inv_log
            (item_id, item_name, unit, delta, stock_after,
             source, transaction_id, note, created_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (item_id, item_name, unit, delta, stock_after,
          source, transaction_id, note, created_by))


def _deduct_cups_for_sale(transaction_id, items, cashier_name=''):
    """
    Called after a successful checkout.
    For each sold item whose product.unit is in CUP_UNITS,
    deduct 1 cup per unit sold from inv_items.
    """
    try:
        cur = mysql.connection.cursor(DictCursor)
        for item in items:
            product_id = item.get('product_id')
            quantity   = int(item.get('quantity', 1))
            if not product_id or quantity <= 0:
                continue
            # Look up the product's unit
            cur.execute("SELECT unit FROM products WHERE product_id=%s AND is_active=1", (product_id,))
            row = cur.fetchone()
            if not row or row['unit'] not in CUP_UNITS:
                continue
            cup_unit = row['unit']
            # Find matching packaging item
            cur.execute(
                "SELECT id, name, stock FROM inv_items WHERE unit=%s AND type='packaging' AND is_active=1 LIMIT 1",
                (cup_unit,)
            )
            cup = cur.fetchone()
            if not cup:
                continue   # Cup item not initialised yet — skip silently
            new_stock = max(0, float(cup['stock']) - quantity)
            cur.execute("UPDATE inv_items SET stock=%s WHERE id=%s", (new_stock, cup['id']))
            _log_inv_change(
                cur,
                item_id=cup['id'],
                item_name=cup['name'],
                unit=cup_unit,
                delta=-quantity,
                stock_after=new_stock,
                source='sale',
                transaction_id=transaction_id,
                note=f"Auto-deducted from TXN #{transaction_id}",
                created_by=cashier_name,
            )
        mysql.connection.commit()
        cur.close()
    except Exception as exc:
        app.logger.error(f"[inv] _deduct_cups_for_sale TXN#{transaction_id}: {exc}")


# ── GET /api/inv_items ────────────────────────────────────────

@app.route('/api/inv_items', methods=['GET'])
def api_inv_items_list():
    """Return all active inventory items (ingredients + packaging)."""
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("""
            SELECT id, name, type, stock, unit, reorder_point, note, updated_at
            FROM inv_items
            WHERE is_active = 1
            ORDER BY type, name
        """)
        items = cur.fetchall()
        cur.close()
        # Attach status label
        for item in items:
            s = float(item['stock'])
            r = float(item['reorder_point'])
            item['status'] = 'out' if s <= 0 else ('low' if s <= r else 'ok')
            item['stock'] = float(item['stock'])
            item['reorder_point'] = float(item['reorder_point'])
        return jsonify({'success': True, 'items': items})
    except Exception as exc:
        app.logger.error(f"[inv_items] list: {exc}")
        return jsonify({'success': False, 'message': str(exc)}), 500


# ── POST /api/inv_items ───────────────────────────────────────

@app.route('/api/inv_items', methods=['POST'])
def api_inv_items_create():
    """Create a new inventory item."""
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'message': 'Name is required'}), 400
    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("""
            INSERT INTO inv_items (name, type, stock, unit, reorder_point, note)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (
            name,
            data.get('type', 'ingredient'),
            float(data.get('stock', 0) or 0),
            (data.get('unit') or 'pcs').strip(),
            float(data.get('reorder_point', 10) or 10),
            (data.get('note') or '').strip() or None,
        ))
        mysql.connection.commit()
        new_id = cur.lastrowid
        cur.close()
        return jsonify({'success': True, 'id': new_id, 'message': f'"{name}" added to inventory'})
    except Exception as exc:
        app.logger.error(f"[inv_items] create: {exc}")
        return jsonify({'success': False, 'message': str(exc)}), 500


# ── PUT /api/inv_items/<id> ───────────────────────────────────

@app.route('/api/inv_items/<int:item_id>', methods=['PUT'])
def api_inv_items_update(item_id):
    """Update an existing inventory item."""
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'message': 'Name is required'}), 400
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE inv_items
               SET name=%s, type=%s, stock=%s, unit=%s, reorder_point=%s, note=%s
             WHERE id=%s AND is_active=1
        """, (
            name,
            data.get('type', 'ingredient'),
            float(data.get('stock', 0) or 0),
            (data.get('unit') or 'pcs').strip(),
            float(data.get('reorder_point', 10) or 10),
            (data.get('note') or '').strip() or None,
            item_id,
        ))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return jsonify({'success': False, 'message': 'Item not found'}), 404
        return jsonify({'success': True, 'message': f'"{name}" updated'})
    except Exception as exc:
        app.logger.error(f"[inv_items] update #{item_id}: {exc}")
        return jsonify({'success': False, 'message': str(exc)}), 500


# ── DELETE /api/inv_items/<id> ────────────────────────────────

@app.route('/api/inv_items/<int:item_id>', methods=['DELETE'])
def api_inv_items_delete(item_id):
    """Soft-delete an inventory item."""
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE inv_items SET is_active=0 WHERE id=%s", (item_id,))
        mysql.connection.commit()
        affected = cur.rowcount
        cur.close()
        if affected == 0:
            return jsonify({'success': False, 'message': 'Item not found'}), 404
        return jsonify({'success': True, 'message': 'Item removed'})
    except Exception as exc:
        app.logger.error(f"[inv_items] delete #{item_id}: {exc}")
        return jsonify({'success': False, 'message': str(exc)}), 500


# ── POST /api/inv_items/adjust ────────────────────────────────

@app.route('/api/inv_items/adjust', methods=['POST'])
def api_inv_items_adjust():
    """
    Manually adjust stock level.
    Body: { id, delta (signed float), note }
    """
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    item_id = data.get('id')
    try:
        delta = float(data.get('delta', 0))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'Invalid delta'}), 400
    if not item_id:
        return jsonify({'success': False, 'message': 'id required'}), 400
    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT id, name, stock, unit FROM inv_items WHERE id=%s AND is_active=1", (item_id,))
        item = cur.fetchone()
        if not item:
            cur.close()
            return jsonify({'success': False, 'message': 'Item not found'}), 404
        new_stock = max(0, float(item['stock']) + delta)
        cur.execute("UPDATE inv_items SET stock=%s WHERE id=%s", (new_stock, item_id))
        _log_inv_change(
            cur,
            item_id=item['id'],
            item_name=item['name'],
            unit=item['unit'],
            delta=delta,
            stock_after=new_stock,
            source='manual',
            note=(data.get('note') or '').strip() or None,
            created_by=session.get('full_name') or session.get('username') or 'Admin',
        )
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True, 'new_stock': new_stock,
                        'message': f'Stock updated to {new_stock} {item["unit"]}'})
    except Exception as exc:
        app.logger.error(f"[inv_items] adjust #{item_id}: {exc}")
        return jsonify({'success': False, 'message': str(exc)}), 500


# ── GET /api/inv_items/log ────────────────────────────────────

@app.route('/api/inv_items/log', methods=['GET'])
def api_inv_items_log():
    """Return recent inventory deduction log entries."""
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    limit = min(int(request.args.get('limit', 30)), 100)
    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("""
            SELECT log_id, item_name, unit, delta, stock_after, source,
                   transaction_id, note, created_by,
                   DATE_FORMAT(created_at, '%%b %%d, %%Y %%h:%%i %%p') AS created_at
            FROM inv_log
            ORDER BY log_id DESC
            LIMIT %s
        """, (limit,))
        log = cur.fetchall()
        cur.close()
        for row in log:
            row['delta'] = float(row['delta'])
            row['stock_after'] = float(row['stock_after'])
        return jsonify({'success': True, 'log': log})
    except Exception as exc:
        app.logger.error(f"[inv_items] log: {exc}")
        return jsonify({'success': False, 'message': str(exc)}), 500


# ═══════════════════════════════════════════════════════════════
# MODIFY EXISTING /api/pos/checkout
# ═══════════════════════════════════════════════════════════════
#
# In your existing checkout route, AFTER committing the
# transaction and BEFORE returning the response, add:
#
#   _deduct_cups_for_sale(
#       transaction_id = new_transaction_id,
#       items          = payload_items,   # list of dicts with product_id, quantity
#       cashier_name   = session.get('full_name', 'Cashier'),
#   )
#
# Example (inside your existing checkout function):
#
#   mysql.connection.commit()
#   new_id = cur.lastrowid
#   cur.close()
#
#   # ← ADD THIS CALL:
#   _deduct_cups_for_sale(new_id, data.get('items', []), session.get('full_name','Cashier'))
#
#   return jsonify({'success': True, 'transaction_id': new_id, 'receipt': receipt_data})
#
# ═══════════════════════════════════════════════════════════════


# ── Auto-migration (call inside run_auto_migration) ───────────

def _ensure_inv_tables():
    """
    Create inv_items and inv_log tables if they don't exist.
    Call this inside run_auto_migration() at startup.
    """
    try:
        conn = mysql.connection
        cur  = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS `inv_items` (
              `id`            int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
              `name`          varchar(120) NOT NULL,
              `type`          enum('ingredient','packaging') NOT NULL DEFAULT 'ingredient',
              `stock`         decimal(12,2) NOT NULL DEFAULT 0,
              `unit`          varchar(20) NOT NULL DEFAULT 'pcs',
              `reorder_point` decimal(12,2) NOT NULL DEFAULT 10,
              `note`          varchar(255) DEFAULT NULL,
              `is_active`     tinyint(1) NOT NULL DEFAULT 1,
              `created_at`    timestamp NOT NULL DEFAULT current_timestamp(),
              `updated_at`    timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
              PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS `inv_log` (
              `log_id`         int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
              `item_id`        int(10) UNSIGNED NOT NULL,
              `item_name`      varchar(120) NOT NULL DEFAULT '',
              `unit`           varchar(20) NOT NULL DEFAULT 'pcs',
              `delta`          decimal(12,2) NOT NULL,
              `stock_after`    decimal(12,2) NOT NULL,
              `source`         enum('sale','manual') NOT NULL DEFAULT 'manual',
              `transaction_id` int(10) UNSIGNED DEFAULT NULL,
              `note`           varchar(255) DEFAULT NULL,
              `created_by`     varchar(80) DEFAULT NULL,
              `created_at`     timestamp NOT NULL DEFAULT current_timestamp(),
              PRIMARY KEY (`log_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
        """)
        # Seed default cup items if none exist
        cur.execute("SELECT COUNT(*) AS c FROM inv_items WHERE unit IN ('8oz','12oz','16oz')")
        if cur.fetchone()[0] == 0:
            cur.executemany(
                "INSERT INTO inv_items (name, type, stock, unit, reorder_point, note) VALUES (%s,'packaging',0,%s,20,%s)",
                [
                    ('8oz Cup',  '8oz',  'Small cup — auto-deducted on sales'),
                    ('12oz Cup', '12oz', 'Medium cup — auto-deducted on sales'),
                    ('16oz Cup', '16oz', 'Large cup — auto-deducted on sales'),
                ]
            )
        conn.commit()
        cur.close()
        app.logger.info("[migration] inv_items + inv_log tables ready")
    except Exception as exc:
        app.logger.error(f"[migration] _ensure_inv_tables: {exc}")
