//! Vocabulaire public : mots-clés et noms génériques qui ne révèlent rien sur un projet.
//! Un identifiant présent ici n'est jamais pseudonymisé, sauf s'il contient un terme interdit.

use std::collections::HashSet;
use std::sync::OnceLock;

const WORDS: &str = "
abstract alias and as assert async await base begin bool boolean break byte case catch char class
const constexpr continue crate debugger def default defer del delete do double dyn elif else elsif
end enum ensure except explicit export extends extern false final finally float fn for foreach from
func function global go goto if impl implements import in include inline instanceof int interface
internal is lambda let local long loop macro_rules match mod module move mut namespace native new nil
none not null object of operator or override package pass private protected protocol pub public raise
record ref repeat require rescue return sealed select self Self short signed sizeof static str string
struct super switch synchronized template then this throw throws trait transient true try type typedef
typeof undefined union unless unsafe unsigned until use using val var virtual void volatile where while
with yield

u8 u16 u32 u64 u128 usize i8 i16 i32 i64 i128 isize f32 f64 int8 int16 int32 int64 uint uint8 uint16
uint32 uint64 float32 float64 size_t ssize_t number bigint any unknown never symbol map chan rune error

String Vec Option Some None Result Ok Err Box Rc Arc Mutex RwLock Cell RefCell HashMap HashSet BTreeMap
BTreeSet VecDeque Clone Copy Debug Display Default Eq PartialEq Ord PartialOrd Hash Iterator Into From
Send Sync Sized Drop Fn FnMut FnOnce Path PathBuf Serialize Deserialize True False Exception Error
Object Array Map Set Promise Date Math JSON Number Boolean Symbol RegExp List Dict Tuple Integer Long
Double Float Char Byte Void Any

main lib index test tests spec src source sources app apps core common utils util helper helpers config
configs settings types models views controllers components services pages public assets static styles
scripts bin build dist target docs doc example examples init setup server client api cli web ui

name value key data id idx index count len length size item items list result results res req request
response input output args argv kwargs arg param params opts options option ctx context state status
err error e ex msg message text content body str buf buffer line lines path file files dir url uri
i j k n m x y z a b c d f g h p q r s t u v w tmp temp old prev next first last start stop self_
get set put post patch add remove insert push pop clear contains join split trim map filter reduce
find sort print println printf format log info warn debug trace read write open close run exec call
new_ to_string from_str as_str as_ref clone iter into_iter unwrap expect collect parse length_ title
type_ class_ cls obj node tree root parent child children left right user users password email
time date timestamp year month day hour minute second min max sum avg total num flag ok fail

headers header method target current props style className innerHTML innerText href src alt width height
top bottom onClick onChange onSubmit children ref stdout stderr stdin env argv code cause stack json
html xml csv yaml toml http https host port timeout retries encoding utf8 mode version enabled disabled
visible hidden checked selected required disabled placeholder label color background border margin padding
display position shape dtype columns rows row col column columns0 values keys entries query params0
capacity is_empty is_some is_none is_ok is_err
";

fn set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| WORDS.split_whitespace().collect())
}

pub fn is_public(word: &str) -> bool {
    set().contains(word)
}
