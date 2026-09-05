import fs from 'fs';
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

function getEnclosingName(node, ancestors) {
    if (node.id && node.id.name) {
        return node.id.name;
    }

    const parent = ancestors[ancestors.length - 2];
    if (!parent) return 'anonymous';

    if (parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier') {
        return parent.id.name;
    }

    if (parent.type === 'AssignmentExpression' && parent.left.type === 'Identifier') {
        return parent.left.name;
    }

    if (
        parent.type === 'AssignmentExpression' &&
        parent.left.type === 'MemberExpression' &&
        parent.left.property.type === 'Identifier'
    ) {
        return parent.left.property.name;
    }

    if (parent.type === 'Property' && parent.key.type === 'Identifier') {
        return parent.key.name;
    }

    if (parent.type === 'MethodDefinition' && parent.key.type === 'Identifier') {
        return parent.key.name;
    }

    return 'anonymous';
}

export function getFunctionNameAtLocation(filePath , targetLine){
       const source = fs.readFileSync(filePath , 'utf-8');

       let ast ;
       try{
          ast = acorn.parse(source , {
              ecmaVersion : 'latest',
              sourceType : 'module',
              locations : true,
              allowReturnOutsideFunction : true,
          });
       }
       catch(error){
          console.warn(`Failed to parse ${filePath}: ${error.message}`);
          return null;
       }

       const candidates = [];

       walk.ancestor(ast , {
            FunctionDeclaration(node, state, ancestors) {
            candidates.push({ node, ancestors: [...ancestors] });
            },
            FunctionExpression(node, state, ancestors) {
                candidates.push({ node, ancestors: [...ancestors] });
            },
            ArrowFunctionExpression(node, state, ancestors) {
                candidates.push({ node, ancestors: [...ancestors] });
            },
       });

        const enclosing = candidates.filter(
            ({node}) => node.loc.start.line <= targetLine && node.loc.end.line >= targetLine
        );

        if(enclosing.length === 0)return null;
        enclosing.sort(
             (a,b) => 
                  (a.node.loc.end.line  - a.node.loc.start.line) - 
                  (b.node.loc.end.line - b.node.loc.start.line)
        );

        const {node , ancestors} = enclosing[0];
        return getEnclosingName(node , ancestors);
}



export function extractAdvisoryFunctionNames(advisorySummary = '', advisoryDetails = '') {
    const text = `${advisorySummary}\n${advisoryDetails}`;
    const names = new Set();
    for (const match of text.matchAll(/`([a-zA-Z_$][\w$]*)`/g)) {
        names.add(match[1]);
    }
    return names;
}