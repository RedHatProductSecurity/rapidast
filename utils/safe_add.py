import ast
import operator as op


def safe_add(expr):
    return _eval(ast.parse(expr, mode="eval").body)


def _eval(node):
    if isinstance(node, ast.Num):  # <number>
        return node.n
    elif isinstance(node, ast.BinOp):  # <left> +/- <right>
        if isinstance(node.op, ast.Add):
            return op.add(_eval(node.left), _eval(node.right))
        elif isinstance(node.op, ast.Sub):
            return op.sub(_eval(node.left), _eval(node.right))
    elif isinstance(node, ast.UnaryOp):  # <operator> <operand> e.g., -/+ 1
        if isinstance(node.op, ast.UAdd):
            return op.pos(_eval(node.operand))
        elif isinstance(node.op, ast.USub):
            return op.neg(_eval(node.operand))
    else:
        raise TypeError(node)
