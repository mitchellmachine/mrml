extern crate proc_macro;

use proc_macro::{TokenStream, TokenTree};

#[proc_macro_attribute]
pub fn export(arguments: TokenStream, item: TokenStream) -> TokenStream {
    let mut tokens = arguments.into_iter();
    let valid = matches!(tokens.next(), Some(TokenTree::Ident(name)) if name.to_string() == "version")
        && matches!(tokens.next(), Some(TokenTree::Punct(equal)) if equal.as_char() == '=')
        && matches!(tokens.next(), Some(TokenTree::Literal(version)) if version.to_string() == "1")
        && tokens.next().is_none();
    if valid {
        item
    } else {
        "compile_error!(\"mrml_abi::export requires version = 1\");"
            .parse()
            .expect("static facade diagnostic parses")
    }
}
